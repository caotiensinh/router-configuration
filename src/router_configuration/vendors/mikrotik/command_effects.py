from __future__ import annotations

from dataclasses import dataclass, replace
from typing import Iterable

from .script_planner import MikroTikCommandPrimitive, MikroTikScriptContract


@dataclass(frozen=True)
class MikroTikCommandEffect:
    command_id: str
    resource_key: str
    effect: str
    provides: tuple[str, ...] = ()
    requires: tuple[str, ...] = ()
    conflicts: tuple[str, ...] = ()
    management_critical: bool = False
    rollback_group: str = "default"

    def as_dict(self) -> dict[str, object]:
        return {
            "command_id": self.command_id,
            "resource_key": self.resource_key,
            "effect": self.effect,
            "provides": list(self.provides),
            "requires": list(self.requires),
            "conflicts": list(self.conflicts),
            "management_critical": self.management_critical,
            "rollback_group": self.rollback_group,
        }


@dataclass(frozen=True)
class MikroTikEffectFinding:
    code: str
    command_id: str
    detail: str

    def as_dict(self) -> dict[str, str]:
        return {"code": self.code, "command_id": self.command_id, "detail": self.detail}


def _generic(command: MikroTikCommandPrimitive) -> MikroTikCommandEffect:
    return MikroTikCommandEffect(
        command_id=command.command_id,
        resource_key=f"{command.section}:{command.command_id}",
        effect="mutate",
        provides=(f"command:{command.command_id}:done",),
        rollback_group=command.subsystem,
    )


def _effect(command: MikroTikCommandPrimitive) -> MikroTikCommandEffect:
    cid = command.command_id

    if cid == "firewall.00.stage-guard":
        return MikroTikCommandEffect(cid, "firewall:input:stage-guard", "replace_guard", ("firewall:stage_guard",), management_critical=True, rollback_group="firewall")
    if cid == "firewall.01.cleanup-chain":
        return MikroTikCommandEffect(cid, "firewall:managed-chains", "cleanup", ("firewall:chains_clean",), ("firewall:stage_guard",), rollback_group="firewall")
    if cid == "firewall.02.cleanup-address-lists":
        return MikroTikCommandEffect(cid, "firewall:managed-address-lists", "cleanup", ("firewall:address_lists_clean",), ("firewall:stage_guard",), rollback_group="firewall")
    if cid.startswith("firewall.10.management-source."):
        return MikroTikCommandEffect(cid, f"firewall:management-source:{cid.rsplit('.', 1)[-1]}", "create", (), ("firewall:address_lists_clean",), rollback_group="firewall")
    if cid.startswith("firewall.20.wan-service-source."):
        return MikroTikCommandEffect(cid, f"firewall:wan-service-source:{cid.split('source.', 1)[-1]}", "create", (), ("firewall:address_lists_clean",), rollback_group="firewall")
    if cid.startswith("firewall.25.icmp."):
        return MikroTikCommandEffect(cid, f"firewall:icmp-rule:{cid.split('icmp.', 1)[-1]}", "create", (), ("firewall:chains_clean", "firewall:stage_guard"), rollback_group="firewall")
    if cid.startswith("firewall.30.rule."):
        requirements = ["firewall:chains_clean", "firewall:stage_guard"]
        if "management" in cid:
            requirements.append("firewall:management_sources_ready")
        if "wan-service" in cid:
            requirements.append("firewall:wan_service_sources_ready")
        if cid.endswith("040-icmp"):
            requirements.append("firewall:icmp_policy_ready")
        return MikroTikCommandEffect(cid, f"firewall:input-rule:{cid.split('rule.', 1)[-1]}", "create", (), tuple(requirements), rollback_group="firewall")
    if cid == "firewall.90.activate-chain":
        return MikroTikCommandEffect(cid, "firewall:input:managed-jump", "activate", ("firewall:managed_input_active",), ("firewall:input_policy_ready", "firewall:stage_guard"), management_critical=True, rollback_group="firewall")
    if cid == "firewall.99.remove-stage-guard":
        return MikroTikCommandEffect(cid, "firewall:input:stage-guard", "remove_guard", ("firewall:stage_guard_released",), ("firewall:managed_input_active",), management_critical=True, rollback_group="firewall")

    if cid == "vlan.00.bridge":
        return MikroTikCommandEffect(cid, "bridge:managed", "create", ("vlan:bridge_ready",), management_critical=True, rollback_group="vlan")
    if cid.startswith("vlan.10.port."):
        return MikroTikCommandEffect(cid, f"bridge-port:{cid.split('port.', 1)[-1]}", "create", (), ("vlan:bridge_ready",), management_critical=True, rollback_group="vlan")
    if cid.startswith("vlan.20.membership."):
        return MikroTikCommandEffect(cid, f"bridge-vlan:{cid.rsplit('.', 1)[-1]}", "create", (), ("vlan:bridge_ready", "vlan:ports_ready"), management_critical=True, rollback_group="vlan")
    if cid == "vlan.30.management-interface":
        return MikroTikCommandEffect(cid, "vlan-interface:management", "create", ("vlan:management_interface_ready",), ("vlan:memberships_ready",), management_critical=True, rollback_group="vlan")
    if cid == "vlan.31.management-address":
        return MikroTikCommandEffect(cid, "ip-address:management-vlan", "create", ("vlan:management_address_ready",), ("vlan:management_interface_ready",), management_critical=True, rollback_group="vlan")
    if cid == "vlan.99.activate-filtering":
        return MikroTikCommandEffect(cid, "bridge:vlan-filtering", "activate", ("vlan:filtering_active",), ("vlan:ports_ready", "vlan:memberships_ready", "vlan:management_address_ready"), management_critical=True, rollback_group="vlan")

    if cid == "wireguard.10.interface":
        return MikroTikCommandEffect(cid, "wireguard:interface", "upsert", ("wireguard:interface_ready",), management_critical=True, rollback_group="wireguard")
    if cid.startswith("wireguard.20.address."):
        return MikroTikCommandEffect(cid, f"wireguard:address:{cid.rsplit('.', 1)[-1]}", "upsert", (), ("wireguard:interface_ready",), management_critical=True, rollback_group="wireguard")
    if cid.startswith("wireguard.30.peer."):
        return MikroTikCommandEffect(cid, f"wireguard:peer:{cid.rsplit('.', 1)[-1]}", "upsert", (), ("wireguard:interface_ready", "wireguard:addresses_ready"), management_critical=True, rollback_group="wireguard")
    if cid.startswith("wireguard.40.route."):
        return MikroTikCommandEffect(cid, f"wireguard:route:{cid.split('route.', 1)[-1]}", "upsert", (), ("wireguard:peers_ready",), management_critical=True, rollback_group="wireguard")

    return _generic(command)


def _mark_group_ready(
    effects: list[MikroTikCommandEffect],
    *,
    prefix: str,
    capability: str,
) -> None:
    matches = [index for index, item in enumerate(effects) if item.command_id.startswith(prefix)]
    if not matches:
        return
    index = matches[-1]
    current = effects[index]
    effects[index] = replace(current, provides=tuple((*current.provides, capability)))


def command_effects(contract: MikroTikScriptContract) -> tuple[MikroTikCommandEffect, ...]:
    effects = [_effect(command) for command in contract.commands]
    _mark_group_ready(effects, prefix="firewall.10.management-source.", capability="firewall:management_sources_ready")
    _mark_group_ready(effects, prefix="firewall.20.wan-service-source.", capability="firewall:wan_service_sources_ready")
    _mark_group_ready(effects, prefix="firewall.25.icmp.", capability="firewall:icmp_policy_ready")
    _mark_group_ready(effects, prefix="firewall.30.rule.", capability="firewall:input_policy_ready")
    _mark_group_ready(effects, prefix="vlan.10.port.", capability="vlan:ports_ready")
    _mark_group_ready(effects, prefix="vlan.20.membership.", capability="vlan:memberships_ready")
    _mark_group_ready(effects, prefix="wireguard.20.address.", capability="wireguard:addresses_ready")
    _mark_group_ready(effects, prefix="wireguard.30.peer.", capability="wireguard:peers_ready")
    return tuple(effects)


def validate_effect_order(
    contract: MikroTikScriptContract,
    ordered_command_ids: Iterable[str],
) -> tuple[MikroTikEffectFinding, ...]:
    by_id = {item.command_id: item for item in command_effects(contract)}
    order = tuple(ordered_command_ids)
    if set(order) != set(by_id) or len(order) != len(by_id):
        return (
            MikroTikEffectFinding(
                "effect_command_set_mismatch",
                "<transaction>",
                "effect graph command set differs from ordered command set",
            ),
        )

    # A requirement may be either transaction-local or an externally verified
    # precondition. The effect graph owns ordering only when this transaction
    # contains a producer for the capability. External prerequisites are checked
    # by discovery/readiness/preflight, not guessed as missing by the script graph.
    transaction_provides = {
        capability
        for effect in by_id.values()
        for capability in effect.provides
    }

    available: set[str] = set()
    active_conflict_tokens: set[str] = set()
    findings: list[MikroTikEffectFinding] = []
    for command_id in order:
        effect = by_id[command_id]
        local_requirements = set(effect.requires) & transaction_provides
        missing = sorted(local_requirements - available)
        if missing:
            findings.append(
                MikroTikEffectFinding(
                    "missing_requirement",
                    command_id,
                    "transaction-local capabilities not yet provided: " + ", ".join(missing),
                )
            )
        conflict = sorted(set(effect.conflicts) & active_conflict_tokens)
        if conflict:
            findings.append(
                MikroTikEffectFinding(
                    "active_conflict",
                    command_id,
                    "conflicting capabilities/resources are active: " + ", ".join(conflict),
                )
            )
        available.update(effect.provides)
        active_conflict_tokens.add(effect.resource_key)

    return tuple(findings)
