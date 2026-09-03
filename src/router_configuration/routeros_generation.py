from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from typing import Any, Mapping

from .render_readiness import assess_render_readiness
from .routeros_firewall_renderer import RouterOSFirewallRenderError, render_routeros_firewall
from .routeros_pcc_renderer import RouterOSPccRenderError, render_routeros_pcc
from .routeros_qos_renderer import RouterOSQoSRenderError, render_routeros_qos
from .routeros_renderer import RouterOSRenderError, RouterOSSafeSubsetRenderer
from .routeros_wireguard_renderer import RouterOSWireGuardRenderError, render_routeros_wireguard


PCC_OPERATION_ID = "routing.multiwan.capacity_weighted"
FIREWALL_OPERATION_ID = "security.baseline"
WIREGUARD_OPERATION_ID = "vpn.wireguard"
QOS_OPERATION_ID = "qos.policy"


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


def _firewall_has_explicit_facts(ir: Mapping[str, Any]) -> bool:
    """Return true only when the operator supplied both mandatory firewall fact sets."""

    operations = ir.get("operations", [])
    if not isinstance(operations, list):
        return False
    for operation in operations:
        if not isinstance(operation, Mapping):
            continue
        if str(operation.get("operation_id") or "") != FIREWALL_OPERATION_ID:
            continue
        attributes = operation.get("attributes", {})
        if not isinstance(attributes, Mapping):
            return False
        management_sources = attributes.get("management_sources")
        required_wan_services = attributes.get("required_wan_services")
        return (
            isinstance(management_sources, list)
            and bool(management_sources)
            and isinstance(required_wan_services, list)
        )
    return False


def _wireguard_has_explicit_facts(ir: Mapping[str, Any]) -> bool:
    operations = ir.get("operations", [])
    if not isinstance(operations, list):
        return False
    for operation in operations:
        if not isinstance(operation, Mapping):
            continue
        if str(operation.get("operation_id") or "") != WIREGUARD_OPERATION_ID:
            continue
        attributes = operation.get("attributes", {})
        references = operation.get("secret_references", [])
        if not isinstance(attributes, Mapping) or attributes.get("enabled") is not True:
            return False
        return (
            bool(str(attributes.get("name") or "").strip())
            and isinstance(attributes.get("addresses"), list)
            and bool(attributes.get("addresses"))
            and isinstance(attributes.get("listen_port"), int)
            and not isinstance(attributes.get("listen_port"), bool)
            and isinstance(attributes.get("mtu"), int)
            and not isinstance(attributes.get("mtu"), bool)
            and isinstance(attributes.get("peers"), list)
            and bool(attributes.get("peers"))
            and isinstance(references, list)
            and len(references) == 1
        )
    return False


def _qos_has_explicit_facts(ir: Mapping[str, Any]) -> bool:
    operations = ir.get("operations", [])
    if not isinstance(operations, list):
        return False
    qos_seen = False
    wan_seen = False
    for operation in operations:
        if not isinstance(operation, Mapping):
            continue
        resource = str(operation.get("resource") or "")
        attributes = operation.get("attributes", {})
        if not isinstance(attributes, Mapping):
            continue
        if str(operation.get("operation_id") or "") == QOS_OPERATION_ID:
            qos_seen = str(attributes.get("policy") or "") == "latency_sensitive_first"
        if resource == "wan_role":
            capacity = attributes.get("capacity_mbps")
            wan_seen = wan_seen or (
                bool(str(attributes.get("name") or "").strip())
                and bool(str(attributes.get("interface") or "").strip())
                and isinstance(capacity, int)
                and not isinstance(capacity, bool)
                and capacity > 0
            )
    return qos_seen and wan_seen


def _command_ids(commands: list[Any], *, label: str, error_type: type[ValueError]) -> set[str]:
    ids = {
        str(item.get("command_id") or "")
        for item in commands
        if isinstance(item, Mapping)
    }
    if len(ids) != len(commands) or "" in ids:
        raise error_type(f"{label} command IDs must be present and unique")
    return ids


def _remove_exact_blocker(
    *,
    base_plan: Mapping[str, Any],
    operation_id: str,
    label: str,
    error_type: type[ValueError],
) -> list[Any]:
    blockers = base_plan.get("blocked_operations", [])
    if not isinstance(blockers, list):
        raise error_type("base renderer blockers must be a list")
    matches = [
        item
        for item in blockers
        if isinstance(item, Mapping)
        and str(item.get("operation_id") or "") == operation_id
    ]
    if len(matches) != 1:
        raise error_type(f"{label} merge requires exactly one explicit deferral blocker")
    return [item for item in blockers if item not in matches]


def _merge_firewall_baseline(
    *,
    base_plan: Mapping[str, Any],
    firewall_plan: Mapping[str, Any],
) -> dict[str, Any]:
    """Merge a pure generation-only firewall extension after topology commands."""

    merged = dict(base_plan)
    base_commands = base_plan.get("commands", [])
    firewall_commands = firewall_plan.get("commands", [])
    if not isinstance(base_commands, list) or not isinstance(firewall_commands, list):
        raise RouterOSFirewallRenderError("base/firewall command collections must be lists")

    base_ids = _command_ids(base_commands, label="base", error_type=RouterOSFirewallRenderError)
    firewall_ids = _command_ids(
        firewall_commands,
        label="firewall",
        error_type=RouterOSFirewallRenderError,
    )
    overlap = sorted(base_ids & firewall_ids)
    if overlap:
        raise RouterOSFirewallRenderError(
            "firewall command IDs collide with base renderer: " + ", ".join(overlap)
        )

    remaining_blockers = _remove_exact_blocker(
        base_plan=base_plan,
        operation_id=FIREWALL_OPERATION_ID,
        label="firewall",
        error_type=RouterOSFirewallRenderError,
    )

    merged_commands = [*base_commands, *firewall_commands]
    merged["commands"] = merged_commands
    merged["blocked_operations"] = remaining_blockers
    merged["claim"] = "generation_complete" if not remaining_blockers else "generation_partial"
    merged["complete"] = not remaining_blockers
    merged["vendor_commands_present"] = bool(merged_commands)

    existing_extensions = merged.get("generation_extensions", {})
    if existing_extensions is None:
        existing_extensions = {}
    if not isinstance(existing_extensions, Mapping):
        raise RouterOSFirewallRenderError("generation_extensions must be an object")
    extensions = dict(existing_extensions)
    if "enterprise_firewall" in extensions:
        raise RouterOSFirewallRenderError("enterprise firewall extension already exists")
    extensions["enterprise_firewall"] = {
        "schema_version": str(firewall_plan.get("schema_version") or ""),
        "command_count": len(firewall_commands),
        "policy": str(firewall_plan.get("policy") or ""),
        "icmp_policy": str(firewall_plan.get("icmp_policy") or ""),
        "source": "explicit_operator_facts",
        "transport_present": False,
        "apply_available": False,
        "write_authorized": False,
    }
    merged["generation_extensions"] = extensions
    merged.pop("render_sha256", None)
    merged["render_sha256"] = _canonical_sha256(merged)
    return merged


def _attach_deferred_wireguard_templates(
    *,
    base_plan: Mapping[str, Any],
    wireguard_plan: Mapping[str, Any],
) -> dict[str, Any]:
    """Attach validated templates while deliberately retaining the WG blocker."""

    merged = dict(base_plan)
    templates = wireguard_plan.get("command_templates", [])
    bindings = wireguard_plan.get("secret_bindings", {})
    if not isinstance(templates, list) or not templates:
        raise RouterOSWireGuardRenderError("WireGuard deferred plan requires command templates")
    if not isinstance(bindings, Mapping) or len(bindings) != 1:
        raise RouterOSWireGuardRenderError("WireGuard deferred plan requires exactly one unresolved secret binding")
    if wireguard_plan.get("secrets_resolved") is not False:
        raise RouterOSWireGuardRenderError("WireGuard deferred plan unexpectedly resolved a secret")

    template_ids = _command_ids(templates, label="WireGuard template", error_type=RouterOSWireGuardRenderError)
    normal_commands = merged.get("commands", [])
    if not isinstance(normal_commands, list):
        raise RouterOSWireGuardRenderError("base renderer commands must be a list")
    normal_ids = _command_ids(normal_commands, label="base", error_type=RouterOSWireGuardRenderError)
    overlap = sorted(template_ids & normal_ids)
    if overlap:
        raise RouterOSWireGuardRenderError(
            "WireGuard template IDs collide with executable generation commands: " + ", ".join(overlap)
        )

    blockers = merged.get("blocked_operations", [])
    if not isinstance(blockers, list):
        raise RouterOSWireGuardRenderError("base renderer blockers must be a list")
    matches = [
        (index, item)
        for index, item in enumerate(blockers)
        if isinstance(item, Mapping)
        and str(item.get("operation_id") or "") == WIREGUARD_OPERATION_ID
    ]
    if len(matches) != 1:
        raise RouterOSWireGuardRenderError(
            "deferred WireGuard attachment requires exactly one explicit base blocker"
        )
    blocker_index, _ = matches[0]
    narrowed = list(blockers)
    narrowed[blocker_index] = {
        "operation_id": WIREGUARD_OPERATION_ID,
        "reason": (
            "WireGuard runtime facts are validated, but the private-key secret binding and "
            "transactional apply boundary remain intentionally unavailable during generation"
        ),
        "required_inputs": ["wireguard.private_key_secret_binding", "transaction.authorized_apply_boundary"],
    }
    merged["blocked_operations"] = narrowed
    merged["claim"] = "generation_partial"
    merged["complete"] = False

    existing = merged.get("deferred_generation_extensions", {})
    if existing is None:
        existing = {}
    if not isinstance(existing, Mapping):
        raise RouterOSWireGuardRenderError("deferred_generation_extensions must be an object")
    extensions = dict(existing)
    if "wireguard" in extensions:
        raise RouterOSWireGuardRenderError("deferred WireGuard extension already exists")
    extensions["wireguard"] = {
        "schema_version": str(wireguard_plan.get("schema_version") or ""),
        "scope": str(wireguard_plan.get("scope") or ""),
        "interface_name": str(wireguard_plan.get("interface_name") or ""),
        "listen_port": wireguard_plan.get("listen_port"),
        "addresses": list(wireguard_plan.get("addresses", [])),
        "peers": [dict(item) for item in wireguard_plan.get("peers", []) if isinstance(item, Mapping)],
        "command_templates": [dict(item) for item in templates if isinstance(item, Mapping)],
        "secret_bindings": {str(key): dict(value) for key, value in bindings.items() if isinstance(value, Mapping)},
        "source": "explicit_operator_facts_unresolved_secret",
        "secrets_resolved": False,
        "transport_present": False,
        "apply_available": False,
        "write_authorized": False,
    }
    merged["deferred_generation_extensions"] = extensions
    merged.pop("render_sha256", None)
    merged["render_sha256"] = _canonical_sha256(merged)
    return merged


def _merge_qos_policy(
    *,
    base_plan: Mapping[str, Any],
    qos_plan: Mapping[str, Any],
) -> dict[str, Any]:
    """Merge the CHR-targeted parent-default QoS formulation into generation output."""

    merged = dict(base_plan)
    base_commands = base_plan.get("commands", [])
    qos_commands = qos_plan.get("commands", [])
    if not isinstance(base_commands, list) or not isinstance(qos_commands, list) or not qos_commands:
        raise RouterOSQoSRenderError("base/QoS command collections must be non-empty lists")

    base_ids = _command_ids(base_commands, label="base", error_type=RouterOSQoSRenderError)
    qos_ids = _command_ids(qos_commands, label="QoS", error_type=RouterOSQoSRenderError)
    overlap = sorted(base_ids & qos_ids)
    if overlap:
        raise RouterOSQoSRenderError(
            "QoS command IDs collide with base renderer: " + ", ".join(overlap)
        )

    remaining_blockers = _remove_exact_blocker(
        base_plan=base_plan,
        operation_id=QOS_OPERATION_ID,
        label="QoS",
        error_type=RouterOSQoSRenderError,
    )
    merged_commands = [*base_commands, *qos_commands]
    merged["commands"] = merged_commands
    merged["blocked_operations"] = remaining_blockers
    merged["claim"] = "generation_complete" if not remaining_blockers else "generation_partial"
    merged["complete"] = not remaining_blockers
    merged["vendor_commands_present"] = bool(merged_commands)

    existing_extensions = merged.get("generation_extensions", {})
    if existing_extensions is None:
        existing_extensions = {}
    if not isinstance(existing_extensions, Mapping):
        raise RouterOSQoSRenderError("generation_extensions must be an object")
    extensions = dict(existing_extensions)
    if "qos" in extensions:
        raise RouterOSQoSRenderError("QoS generation extension already exists")
    extensions["qos"] = {
        "schema_version": str(qos_plan.get("schema_version") or ""),
        "command_count": len(qos_commands),
        "policy": str(qos_plan.get("policy") or ""),
        "strategy": str(qos_plan.get("strategy") or ""),
        "policy_contract": dict(qos_plan.get("policy_contract", {}))
        if isinstance(qos_plan.get("policy_contract"), Mapping)
        else {},
        "targets": [dict(item) for item in qos_plan.get("targets", []) if isinstance(item, Mapping)],
        "source": "verified_ir_topology_and_product_policy",
        "default_traffic_marked": False,
        "transport_present": False,
        "apply_available": False,
        "write_authorized": False,
    }
    merged["generation_extensions"] = extensions
    merged.pop("render_sha256", None)
    merged["render_sha256"] = _canonical_sha256(merged)
    return merged


def _merge_state_bound_pcc(
    *,
    base_plan: Mapping[str, Any],
    pcc_plan: Mapping[str, Any],
) -> dict[str, Any]:
    """Merge the CHR-verified PCC extension after live-state safety checks."""

    merged = dict(base_plan)
    base_commands = base_plan.get("commands", [])
    pcc_commands = pcc_plan.get("commands", [])
    if not isinstance(base_commands, list) or not isinstance(pcc_commands, list):
        raise RouterOSPccRenderError("base/PCC command collections must be lists")

    base_ids = _command_ids(base_commands, label="base", error_type=RouterOSPccRenderError)
    pcc_ids = _command_ids(pcc_commands, label="PCC", error_type=RouterOSPccRenderError)
    overlap = sorted(base_ids & pcc_ids)
    if overlap:
        raise RouterOSPccRenderError(
            "state-bound PCC command IDs collide with base renderer: " + ", ".join(overlap)
        )

    remaining_blockers = _remove_exact_blocker(
        base_plan=base_plan,
        operation_id=PCC_OPERATION_ID,
        label="state-bound PCC",
        error_type=RouterOSPccRenderError,
    )

    merged_commands = [*base_commands, *pcc_commands]
    merged["commands"] = merged_commands
    merged["blocked_operations"] = remaining_blockers
    merged["claim"] = "generation_complete" if not remaining_blockers else "generation_partial"
    merged["complete"] = not remaining_blockers
    merged["vendor_commands_present"] = bool(merged_commands)

    existing_extensions = merged.get("state_bound_extensions", {})
    if existing_extensions is None:
        existing_extensions = {}
    if not isinstance(existing_extensions, Mapping):
        raise RouterOSPccRenderError("state_bound_extensions must be an object")
    extensions = dict(existing_extensions)
    if "capacity_weighted_pcc" in extensions:
        raise RouterOSPccRenderError("capacity-weighted PCC extension already exists")
    extensions["capacity_weighted_pcc"] = {
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
    merged["state_bound_extensions"] = extensions
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

    This boundary deliberately does not accept credentials, URLs, a transport or
    resolved secrets. Stateless base rendering runs first. Explicit firewall
    facts may produce generation-only commands. Explicit WireGuard facts may
    produce only deferred templates while the private-key binding remains
    blocked. QoS binds the product policy to already-compiled WAN topology facts.
    Complete PCC path facts may be bound to already-verified normalized state.
    Unsafe live PCC state such as FastTrack/dstnat fails closed.
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

    if _firewall_has_explicit_facts(ir):
        try:
            firewall_plan = render_routeros_firewall(ir=ir).as_dict()
            plan = _merge_firewall_baseline(base_plan=plan, firewall_plan=firewall_plan)
        except RouterOSFirewallRenderError as exc:
            return RouterOSGenerationResult(
                errors=(f"firewall renderer: {exc}",),
                warnings=readiness_result.warnings,
                readiness=readiness,
            )

    if _wireguard_has_explicit_facts(ir):
        try:
            wireguard_plan = render_routeros_wireguard(ir=ir).as_dict()
            plan = _attach_deferred_wireguard_templates(
                base_plan=plan,
                wireguard_plan=wireguard_plan,
            )
        except RouterOSWireGuardRenderError as exc:
            return RouterOSGenerationResult(
                errors=(f"wireguard renderer: {exc}",),
                warnings=readiness_result.warnings,
                readiness=readiness,
            )

    if _qos_has_explicit_facts(ir):
        try:
            qos_plan = render_routeros_qos(ir=ir).as_dict()
            plan = _merge_qos_policy(base_plan=plan, qos_plan=qos_plan)
        except RouterOSQoSRenderError as exc:
            return RouterOSGenerationResult(
                errors=(f"qos renderer: {exc}",),
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
