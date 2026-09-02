from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from typing import Any, Mapping

from .render_readiness import assess_render_readiness
from .routeros_pcc_renderer import RouterOSPccRenderError, render_routeros_pcc
from .routeros_renderer import RouterOSRenderError, RouterOSSafeSubsetRenderer


PCC_OPERATION_ID = "routing.multiwan.capacity_weighted"


@dataclass(frozen=True)
class RouterOSGenerationResult:
    errors: tuple[str, ...]
    warnings: tuple[str, ...]
    readiness: Mapping[str, Any]
    render_plan: Mapping[str, Any] | None = None

    @property
    def ok(self) -> bool:
        return not self.errors and self.render_plan is not None

    def as_dict(self) -> dict[str, Any]:
        return {
            "ok": self.ok,
            "claim": "routeros_generation_complete" if self.ok else "routeros_generation_blocked",
            "errors": list(self.errors),
            "warnings": list(self.warnings),
            "readiness": dict(self.readiness),
            "render_plan": dict(self.render_plan) if self.render_plan is not None else None,
            "transport_present": False,
            "apply_available": False,
            "write_authorized": False,
        }


def _canonical_sha256(payload: Mapping[str, Any]) -> str:
    canonical = json.dumps(
        payload,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        default=str,
    ).encode("utf-8")
    return hashlib.sha256(canonical).hexdigest()


def _pcc_has_explicit_paths(ir: Mapping[str, Any]) -> bool:
    operations = ir.get("operations", [])
    if not isinstance(operations, list):
        return False
    for operation in operations:
        if not isinstance(operation, Mapping):
            continue
        if str(operation.get("operation_id") or "") != PCC_OPERATION_ID:
            continue
        attributes = operation.get("attributes", {})
        if not isinstance(attributes, Mapping):
            return False
        weights = attributes.get("weights")
        paths = attributes.get("paths")
        return (
            isinstance(weights, Mapping)
            and bool(weights)
            and isinstance(paths, Mapping)
            and set(str(name) for name in paths) == set(str(name) for name in weights)
        )
    return False


def _merge_state_bound_pcc(
    *,
    base_plan: Mapping[str, Any],
    pcc_plan: Mapping[str, Any],
) -> dict[str, Any]:
    """Merge the CHR-verified PCC extension after live-state safety checks.

    Base commands stay first because they create interface lists, routing tables,
    recursive probe routes and failover defaults. PCC policy routes and mangle
    rules are appended only after those prerequisites exist.
    """

    merged = dict(base_plan)
    base_commands = base_plan.get("commands", [])
    pcc_commands = pcc_plan.get("commands", [])
    if not isinstance(base_commands, list) or not isinstance(pcc_commands, list):
        raise RouterOSPccRenderError("base/PCC command collections must be lists")

    base_ids = {
        str(item.get("command_id") or "")
        for item in base_commands
        if isinstance(item, Mapping)
    }
    pcc_ids = {
        str(item.get("command_id") or "")
        for item in pcc_commands
        if isinstance(item, Mapping)
    }
    if "" in base_ids or "" in pcc_ids:
        raise RouterOSPccRenderError("base/PCC command IDs must not be empty")
    overlap = sorted(base_ids & pcc_ids)
    if overlap:
        raise RouterOSPccRenderError(
            "state-bound PCC command IDs collide with base renderer: " + ", ".join(overlap)
        )

    blockers = base_plan.get("blocked_operations", [])
    if not isinstance(blockers, list):
        raise RouterOSPccRenderError("base renderer blockers must be a list")
    pcc_blockers = [
        item
        for item in blockers
        if isinstance(item, Mapping)
        and str(item.get("operation_id") or "") == PCC_OPERATION_ID
    ]
    if len(pcc_blockers) != 1:
        raise RouterOSPccRenderError(
            "state-bound PCC merge requires exactly one explicit PCC deferral blocker"
        )
    remaining_blockers = [item for item in blockers if item not in pcc_blockers]

    merged_commands = [*base_commands, *pcc_commands]
    merged["commands"] = merged_commands
    merged["blocked_operations"] = remaining_blockers
    merged["claim"] = "generation_complete" if not remaining_blockers else "generation_partial"
    merged["complete"] = not remaining_blockers
    merged["vendor_commands_present"] = bool(merged_commands)
    merged["state_bound_extensions"] = {
        "capacity_weighted_pcc": {
            "schema_version": str(pcc_plan.get("schema_version") or ""),
            "command_count": len(pcc_commands),
            "pcc_spec": dict(pcc_plan.get("pcc_spec", {}))
            if isinstance(pcc_plan.get("pcc_spec"), Mapping)
            else {},
            "source": "verified_normalized_state",
            "transport_present": False,
            "apply_available": False,
            "write_authorized": False,
        }
    }
    merged.pop("render_sha256", None)
    merged["render_sha256"] = _canonical_sha256(merged)
    return merged


def generate_routeros_plan(
    *,
    profile: Mapping[str, Any],
    ir: Mapping[str, Any],
    evidence: Mapping[str, Any],
) -> RouterOSGenerationResult:
    """Gate pure RouterOS generation behind verified profile/IR/live-state readiness.

    This boundary deliberately does not accept credentials, URLs or a transport.
    Stateless base rendering runs first. If the IR contains complete PCC path
    facts, the CHR-verified PCC renderer is then bound to the already-verified
    normalized state. Unsafe live state (for example active FastTrack/dstnat)
    fails generation closed instead of silently retaining a deployable PCC plan.
    """

    readiness_result = assess_render_readiness(
        profile=profile,
        ir=ir,
        evidence=evidence,
    )
    readiness = readiness_result.as_dict()
    if not readiness_result.ok:
        return RouterOSGenerationResult(
            errors=readiness_result.errors,
            warnings=readiness_result.warnings,
            readiness=readiness,
        )

    try:
        plan = RouterOSSafeSubsetRenderer().render(ir).as_dict()
    except RouterOSRenderError as exc:
        return RouterOSGenerationResult(
            errors=(f"renderer: {exc}",),
            warnings=readiness_result.warnings,
            readiness=readiness,
        )

    if plan.get("source_ir_sha256") != readiness_result.ir_sha256:
        return RouterOSGenerationResult(
            errors=("renderer source IR digest does not match readiness binding",),
            warnings=readiness_result.warnings,
            readiness=readiness,
        )
    if any(
        plan.get(field) is not expected
        for field, expected in (
            ("secrets_resolved", False),
            ("transport_present", False),
            ("apply_available", False),
            ("write_authorized", False),
        )
    ):
        return RouterOSGenerationResult(
            errors=("renderer plan violated the generation-only safety boundary",),
            warnings=readiness_result.warnings,
            readiness=readiness,
        )

    if _pcc_has_explicit_paths(ir):
        state = evidence.get("normalized_state")
        if not isinstance(state, Mapping):
            return RouterOSGenerationResult(
                errors=("verified normalized_state is required for state-bound PCC generation",),
                warnings=readiness_result.warnings,
                readiness=readiness,
            )
        try:
            pcc_plan = render_routeros_pcc(ir=ir, state=state).as_dict()
            plan = _merge_state_bound_pcc(base_plan=plan, pcc_plan=pcc_plan)
        except RouterOSPccRenderError as exc:
            return RouterOSGenerationResult(
                errors=(f"pcc renderer: {exc}",),
                warnings=readiness_result.warnings,
                readiness=readiness,
            )

    if any(
        plan.get(field) is not expected
        for field, expected in (
            ("secrets_resolved", False),
            ("transport_present", False),
            ("apply_available", False),
            ("write_authorized", False),
        )
    ):
        return RouterOSGenerationResult(
            errors=("state-bound generation violated the generation-only safety boundary",),
            warnings=readiness_result.warnings,
            readiness=readiness,
        )

    return RouterOSGenerationResult(
        errors=(),
        warnings=readiness_result.warnings,
        readiness=readiness,
        render_plan=plan,
    )
