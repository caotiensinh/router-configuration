from __future__ import annotations

import json
from dataclasses import dataclass
from typing import Any, Mapping

from .preflight import RouterOSPreflightEvaluator
from .routeros_state_contract import verify_routeros_discovery_evidence
from .safe_subset_ir import SafeSubsetCompiler


@dataclass(frozen=True)
class RenderReadinessResult:
    errors: tuple[str, ...]
    warnings: tuple[str, ...]
    ir_sha256: str | None = None
    state_sha256: str | None = None

    @property
    def ok(self) -> bool:
        return not self.errors

    def as_dict(self) -> dict[str, Any]:
        return {
            "ok": self.ok,
            "claim": "ready_for_renderer_generation" if self.ok else "renderer_generation_blocked",
            "errors": list(self.errors),
            "warnings": list(self.warnings),
            "ir_sha256": self.ir_sha256,
            "state_sha256": self.state_sha256,
            "renderer_enabled": False,
            "write_authorized": False,
        }


def _is_enabled_flag(value: Any) -> bool:
    if value is True:
        return True
    return str(value or "").strip().lower() in {"1", "true", "yes"}


def _routing_table_safety_errors(
    ir: Mapping[str, Any],
    state: Mapping[str, Any],
) -> tuple[str, ...]:
    """Reject reuse of an existing non-FIB table referenced by Multi-WAN intent.

    The renderer may create a missing dedicated table, but it must not silently
    change the semantics of an existing table. This keeps generation fail-safe
    and leaves any intentional table conversion to an explicit reviewed change.
    """

    tables = state.get("routing_tables", [])
    if not isinstance(tables, list):
        return ()
    existing: dict[str, Mapping[str, Any]] = {}
    for row in tables:
        if not isinstance(row, Mapping):
            continue
        name = str(row.get("name") or "").strip()
        if name:
            existing[name] = row

    errors: list[str] = []
    operations = ir.get("operations", [])
    if not isinstance(operations, list):
        return ()
    for operation in operations:
        if not isinstance(operation, Mapping):
            continue
        if str(operation.get("resource") or "") != "path_distribution_policy":
            continue
        operation_id = str(operation.get("operation_id") or "<unknown>")
        attributes = operation.get("attributes", {})
        if not isinstance(attributes, Mapping):
            continue
        paths = attributes.get("paths")
        if not isinstance(paths, Mapping):
            continue
        for wan_name, path in paths.items():
            if not isinstance(path, Mapping):
                continue
            table = str(path.get("table") or "").strip()
            if not table or table == "main":
                continue
            current = existing.get(table)
            if current is not None and not _is_enabled_flag(current.get("fib")):
                errors.append(
                    f"{operation_id}: existing routing table {table!r} for WAN {str(wan_name)!r} is not FIB-enabled; refuse to alter existing table semantics"
                )
    return tuple(errors)


def assess_render_readiness(
    *,
    profile: Mapping[str, Any],
    ir: Mapping[str, Any],
    evidence: Mapping[str, Any],
) -> RenderReadinessResult:
    """Require trusted inputs before a future vendor renderer may run.

    This gate neither renders vendor commands nor authorizes writes. It binds
    the guided profile to a freshly compiled IR, validates RouterOS evidence,
    runs profile/evidence preflight, and verifies feature prerequisites.
    """

    errors: list[str] = []
    warnings: list[str] = []

    if ir.get("schema_version") != "config-safe-subset-ir/1":
        errors.append("unsupported or missing safe-subset IR schema")
        return RenderReadinessResult(tuple(errors), tuple(warnings))
    if ir.get("vendor_commands_present") is not False:
        errors.append("IR must not contain vendor commands before renderer boundary")
    if ir.get("write_transport_present") is not False:
        errors.append("IR must not contain a write transport")

    try:
        expected_ir = SafeSubsetCompiler().compile(profile).as_dict()
    except ValueError as exc:
        errors.append(f"profile cannot compile to safe-subset IR: {exc}")
        return RenderReadinessResult(tuple(errors), tuple(warnings))

    expected_sha = expected_ir.get("ir_sha256")
    supplied_sha = ir.get("ir_sha256")
    if supplied_sha != expected_sha:
        errors.append("IR digest/profile binding mismatch; regenerate IR from the current profile")
    if json.dumps(ir.get("operations", []), sort_keys=True, default=str) != json.dumps(
        expected_ir.get("operations", []), sort_keys=True, default=str
    ):
        errors.append("IR operations do not match a fresh compilation of the profile")

    verification = verify_routeros_discovery_evidence(evidence)
    if not verification.ok:
        errors.extend(f"evidence: {item}" for item in verification.errors)
        warnings.extend(f"evidence: {item}" for item in verification.warnings)
        return RenderReadinessResult(
            tuple(errors),
            tuple(warnings),
            ir_sha256=str(supplied_sha or "") or None,
            state_sha256=str(evidence.get("state_sha256") or "") or None,
        )

    trusted_state = verification.state if isinstance(verification.state, Mapping) else {}
    errors.extend(_routing_table_safety_errors(ir, trusted_state))

    preflight = RouterOSPreflightEvaluator().evaluate(profile, evidence)
    for finding in preflight.findings:
        if finding.severity.value == "blocking":
            errors.append(f"preflight/{finding.code}: {finding.message}")
        elif finding.severity.value == "warning":
            warnings.append(f"preflight/{finding.code}: {finding.message}")

    capability_payload = evidence.get("capabilities", {})
    capabilities = capability_payload.get("capabilities", {}) if isinstance(capability_payload, Mapping) else {}
    if not isinstance(capabilities, Mapping):
        capabilities = {}

    profile_recovery = profile.get("recovery_access", {})
    management_path_ready = (
        isinstance(profile_recovery, Mapping)
        and profile_recovery.get("documented") is True
        and bool(str(profile_recovery.get("method") or "").strip())
    )

    for operation in ir.get("operations", []):
        if not isinstance(operation, Mapping):
            errors.append("IR contains a non-object operation")
            continue
        operation_id = str(operation.get("operation_id") or "<unknown>")
        for requirement in operation.get("requires", []):
            name = str(requirement)
            if name == "management_path":
                if not management_path_ready:
                    errors.append(f"{operation_id}: documented recovery/management path is required")
                continue
            if name == "nat":
                available = bool(capabilities.get("firewall"))
            elif name == "interfaces":
                state = evidence.get("normalized_state", {})
                available = isinstance(state, Mapping) and isinstance(state.get("interfaces"), list)
            else:
                available = bool(capabilities.get(name))
            if not available:
                errors.append(f"{operation_id}: required capability {name!r} is unavailable")

    return RenderReadinessResult(
        errors=tuple(sorted(set(errors))),
        warnings=tuple(sorted(set(warnings))),
        ir_sha256=str(supplied_sha or "") or None,
        state_sha256=str(evidence.get("state_sha256") or "") or None,
    )
