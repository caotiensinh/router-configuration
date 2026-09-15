from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from typing import Any, Mapping


class RendererCoverageStatus(str, Enum):
    RENDERED = "rendered"
    DEFERRED_EXECUTION_BOUNDARY = "deferred_execution_boundary"
    BLOCKED = "blocked"


@dataclass(frozen=True)
class RendererOperationCoverage:
    operation_id: str
    resource: str
    status: RendererCoverageStatus
    evidence: tuple[str, ...]

    def as_dict(self) -> dict[str, Any]:
        return {
            "operation_id": self.operation_id,
            "resource": self.resource,
            "status": self.status.value,
            "evidence": list(self.evidence),
        }


@dataclass(frozen=True)
class RendererCoverageReport:
    operations: tuple[RendererOperationCoverage, ...]

    @property
    def renderer_complete(self) -> bool:
        return all(item.status is not RendererCoverageStatus.BLOCKED for item in self.operations)

    @property
    def execution_deferred(self) -> bool:
        return any(
            item.status is RendererCoverageStatus.DEFERRED_EXECUTION_BOUNDARY
            for item in self.operations
        )

    def as_dict(self) -> dict[str, Any]:
        return {
            "schema_version": "routeros-renderer-coverage/1",
            "renderer_complete": self.renderer_complete,
            "execution_deferred": self.execution_deferred,
            "operations": [item.as_dict() for item in self.operations],
            "production_writer_available": False,
            "write_authorized": False,
        }


def _operation_rows(ir: Mapping[str, Any]) -> list[Mapping[str, Any]]:
    operations = ir.get("operations")
    if not isinstance(operations, list):
        raise ValueError("safe-subset IR operations must be a list")
    rows: list[Mapping[str, Any]] = []
    seen: set[str] = set()
    for raw in operations:
        if not isinstance(raw, Mapping):
            raise ValueError("safe-subset IR contains a non-object operation")
        operation_id = str(raw.get("operation_id") or "").strip()
        resource = str(raw.get("resource") or "").strip()
        if not operation_id or not resource:
            raise ValueError("every operation requires operation_id and resource")
        if operation_id in seen:
            raise ValueError(f"duplicate operation_id: {operation_id}")
        seen.add(operation_id)
        rows.append(raw)
    return rows


def _accepted_state_bound_extension(
    extensions: Mapping[str, Any],
    name: str,
) -> bool:
    """Require positive generation evidence without accepting a write-capable extension."""

    value = extensions.get(name)
    if not isinstance(value, Mapping):
        return False
    command_count = value.get("command_count")
    return (
        isinstance(command_count, int)
        and not isinstance(command_count, bool)
        and command_count > 0
        and value.get("transport_present") is False
        and value.get("apply_available") is False
        and value.get("write_authorized") is False
    )


def assess_renderer_coverage(
    *,
    ir: Mapping[str, Any],
    render_plan: Mapping[str, Any],
) -> RendererCoverageReport:
    """Account for render coverage without turning execution blockers into syntax gaps.

    WireGuard may have a complete deterministic command-template renderer while its
    secret binding / authorized apply boundary remains intentionally unavailable.
    State-bound VLAN and PBR extensions count as renderer coverage only when their
    accepted extension metadata proves generation-only behavior and a non-empty
    command set. Unknown or otherwise blocked operations remain fail-closed.
    """

    if ir.get("schema_version") != "config-safe-subset-ir/1":
        raise ValueError("unsupported safe-subset IR schema")
    if render_plan.get("schema_version") != "routeros-render-plan/1":
        raise ValueError("unsupported RouterOS render-plan schema")

    commands = render_plan.get("commands", [])
    blockers = render_plan.get("blocked_operations", [])
    if not isinstance(commands, list) or not isinstance(blockers, list):
        raise ValueError("render plan commands/blockers must be lists")

    command_operation_ids = {
        str(item.get("operation_id") or "")
        for item in commands
        if isinstance(item, Mapping) and str(item.get("operation_id") or "")
    }
    blocked_by_id = {
        str(item.get("operation_id") or ""): item
        for item in blockers
        if isinstance(item, Mapping) and str(item.get("operation_id") or "")
    }

    generation_extensions = render_plan.get("generation_extensions", {})
    deferred_extensions = render_plan.get("deferred_generation_extensions", {})
    state_bound_extensions = render_plan.get("state_bound_extensions", {})
    if not isinstance(generation_extensions, Mapping) or not isinstance(deferred_extensions, Mapping):
        raise ValueError("render-plan extension collections must be objects")
    if not isinstance(state_bound_extensions, Mapping):
        raise ValueError("render-plan state_bound_extensions must be an object")

    report: list[RendererOperationCoverage] = []
    for operation in sorted(_operation_rows(ir), key=lambda item: str(item["operation_id"])):
        operation_id = str(operation["operation_id"])
        resource = str(operation["resource"])
        evidence: list[str] = []

        if operation_id in command_operation_ids:
            evidence.append("base_render_commands")

        if operation_id == "routing.multiwan.capacity_weighted":
            if "pcc" in generation_extensions:
                evidence.append("pcc_generation_extension")
            if _accepted_state_bound_extension(
                state_bound_extensions, "capacity_weighted_pcc"
            ):
                evidence.append("capacity_weighted_pcc_state_bound_extension")
        elif operation_id == "security.baseline" and "enterprise_firewall" in generation_extensions:
            evidence.append("enterprise_firewall_generation_extension")
        elif operation_id == "qos.policy" and "qos" in generation_extensions:
            evidence.append("qos_generation_extension")
        elif operation_id == "switching.vlan.segmentation" and _accepted_state_bound_extension(
            state_bound_extensions, "vlan_segmentation"
        ):
            evidence.append("vlan_segmentation_state_bound_extension")
        elif operation_id == "routing.pbr.rules" and _accepted_state_bound_extension(
            state_bound_extensions, "policy_routing"
        ):
            evidence.append("policy_routing_state_bound_extension")

        if evidence and operation_id not in blocked_by_id:
            status = RendererCoverageStatus.RENDERED
        elif (
            operation_id == "vpn.wireguard"
            and "wireguard" in deferred_extensions
            and operation_id in blocked_by_id
        ):
            required = blocked_by_id[operation_id].get("required_inputs", [])
            if not isinstance(required, list):
                raise ValueError("WireGuard blocker required_inputs must be a list")
            expected = {
                "wireguard.private_key_secret_binding",
                "transaction.authorized_apply_boundary",
            }
            if set(str(item) for item in required) != expected:
                status = RendererCoverageStatus.BLOCKED
                evidence.append("unexpected_wireguard_blocker")
            else:
                status = RendererCoverageStatus.DEFERRED_EXECUTION_BOUNDARY
                evidence.extend(("wireguard_command_templates", "unresolved_secret_boundary"))
        else:
            status = RendererCoverageStatus.BLOCKED
            if operation_id in blocked_by_id:
                evidence.append("render_plan_blocker")
            else:
                evidence.append("no_accepted_renderer_evidence")

        report.append(
            RendererOperationCoverage(
                operation_id=operation_id,
                resource=resource,
                status=status,
                evidence=tuple(evidence),
            )
        )

    return RendererCoverageReport(tuple(report))
