from __future__ import annotations

import hashlib
import json
from typing import Any, Mapping

from .routeros_pbr_renderer import RouterOSPbrRenderError, render_routeros_pbr
from .routeros_vlan_renderer import RouterOSVlanRenderError, render_routeros_vlan


VLAN_OPERATION_ID = "switching.vlan.segmentation"
PBR_OPERATION_ID = "routing.pbr.rules"


def _canonical_sha256(payload: Mapping[str, Any]) -> str:
    return hashlib.sha256(
        json.dumps(
            payload,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=False,
            default=str,
        ).encode("utf-8")
    ).hexdigest()


def _has_resource(ir: Mapping[str, Any], resource: str) -> bool:
    operations = ir.get("operations", [])
    return isinstance(operations, list) and any(
        isinstance(item, Mapping) and str(item.get("resource") or "") == resource
        for item in operations
    )


def _remove_blocker(
    plan: Mapping[str, Any],
    *,
    operation_id: str,
    label: str,
    error_type: type[ValueError],
) -> list[Any]:
    blockers = plan.get("blocked_operations", [])
    if not isinstance(blockers, list):
        raise error_type("base renderer blockers must be a list")
    matches = [
        item
        for item in blockers
        if isinstance(item, Mapping)
        and str(item.get("operation_id") or "") == operation_id
    ]
    if len(matches) != 1:
        raise error_type(f"{label} merge requires exactly one explicit base blocker")
    return [item for item in blockers if item not in matches]


def _merge_commands(
    base_plan: Mapping[str, Any],
    extension_plan: Mapping[str, Any],
    *,
    operation_id: str,
    extension_name: str,
    error_type: type[ValueError],
    metadata: Mapping[str, Any],
) -> dict[str, Any]:
    merged = dict(base_plan)
    base_commands = base_plan.get("commands", [])
    extension_commands = extension_plan.get("commands", [])
    if not isinstance(base_commands, list) or not isinstance(extension_commands, list):
        raise error_type("base and extension command collections must be lists")
    if not extension_commands:
        raise error_type(f"{extension_name} extension produced no commands")

    base_ids = {
        str(item.get("command_id") or "")
        for item in base_commands
        if isinstance(item, Mapping)
    }
    extension_ids = {
        str(item.get("command_id") or "")
        for item in extension_commands
        if isinstance(item, Mapping)
    }
    if len(base_ids) != len(base_commands) or "" in base_ids:
        raise error_type("base command IDs must be present and unique")
    if len(extension_ids) != len(extension_commands) or "" in extension_ids:
        raise error_type(f"{extension_name} command IDs must be present and unique")
    overlap = sorted(base_ids & extension_ids)
    if overlap:
        raise error_type(
            f"{extension_name} command IDs collide with base renderer: " + ", ".join(overlap)
        )

    merged["commands"] = [*base_commands, *extension_commands]
    merged["blocked_operations"] = _remove_blocker(
        base_plan,
        operation_id=operation_id,
        label=extension_name,
        error_type=error_type,
    )
    merged["claim"] = "generation_complete" if not merged["blocked_operations"] else "generation_partial"
    merged["complete"] = not merged["blocked_operations"]
    merged["vendor_commands_present"] = bool(merged["commands"])

    existing = merged.get("state_bound_extensions", {})
    if existing is None:
        existing = {}
    if not isinstance(existing, Mapping):
        raise error_type("state_bound_extensions must be an object")
    extensions = dict(existing)
    if extension_name in extensions:
        raise error_type(f"{extension_name} extension already exists")
    extensions[extension_name] = {
        **dict(metadata),
        "schema_version": str(extension_plan.get("schema_version") or ""),
        "command_count": len(extension_commands),
        "source": "verified_normalized_state_and_prerequisites",
        "transport_present": False,
        "apply_available": False,
        "write_authorized": False,
    }
    merged["state_bound_extensions"] = extensions
    merged.pop("render_sha256", None)
    merged["render_sha256"] = _canonical_sha256(merged)
    return merged


def apply_state_bound_vlan_pbr_extensions(
    *,
    base_plan: Mapping[str, Any],
    ir: Mapping[str, Any],
    evidence: Mapping[str, Any],
) -> dict[str, Any]:
    """Attach VLAN/PBR generation-only extensions when explicit intent is present.

    This function never resolves credentials, secrets or write transports. It
    fails closed when the live-state prerequisites required by the standalone
    renderers are not present in evidence.
    """

    plan = dict(base_plan)
    state = evidence.get("normalized_state")
    prerequisites = evidence.get("render_prerequisites")

    if _has_resource(ir, "vlan_segmentation_policy"):
        if not isinstance(state, Mapping):
            raise RouterOSVlanRenderError(
                "verified normalized_state is required for VLAN generation"
            )
        if not isinstance(prerequisites, Mapping):
            raise RouterOSVlanRenderError(
                "verified render_prerequisites are required for VLAN generation"
            )
        management_path = evidence.get("management_path")
        if not isinstance(management_path, Mapping):
            raise RouterOSVlanRenderError(
                "verified management_path evidence is required for VLAN generation"
            )
        vlan_plan = render_routeros_vlan(
            ir=ir,
            state=state,
            prerequisites=prerequisites,
            management_path=management_path,
        ).as_dict()
        plan = _merge_commands(
            plan,
            vlan_plan,
            operation_id=VLAN_OPERATION_ID,
            extension_name="vlan_segmentation",
            error_type=RouterOSVlanRenderError,
            metadata={
                "activation_policy": str(vlan_plan.get("activation_policy") or ""),
                "current_management_interface": str(
                    vlan_plan.get("current_management_interface") or ""
                ),
            },
        )

    if _has_resource(ir, "policy_routing_rules"):
        if not isinstance(state, Mapping):
            raise RouterOSPbrRenderError(
                "verified normalized_state is required for PBR generation"
            )
        if not isinstance(prerequisites, Mapping):
            raise RouterOSPbrRenderError(
                "verified render_prerequisites are required for PBR generation"
            )
        pbr_plan = render_routeros_pbr(
            ir=ir,
            state=state,
            prerequisites=prerequisites,
        ).as_dict()
        plan = _merge_commands(
            plan,
            pbr_plan,
            operation_id=PBR_OPERATION_ID,
            extension_name="policy_routing",
            error_type=RouterOSPbrRenderError,
            metadata={
                "strategy": str(pbr_plan.get("strategy") or ""),
                "mangle_routing_marks": bool(pbr_plan.get("mangle_routing_marks")),
            },
        )

    for field, expected in (
        ("transport_present", False),
        ("apply_available", False),
        ("write_authorized", False),
    ):
        if plan.get(field) is not expected:
            raise ValueError("VLAN/PBR extension violated generation-only safety boundary")
    return plan
