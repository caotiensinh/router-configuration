from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class TroubleshootingPlaybook:
    name: str
    features: tuple[str, ...]
    evidence_nodes: tuple[str, ...]
    capture_default: bool = False


_PLAYBOOKS = {
    "client_no_internet": TroubleshootingPlaybook(
        "client_no_internet",
        ("inventory", "interface", "internet", "routing", "firewall", "diagnostic"),
        ("device_inventory", "interface_state", "addressing", "routing", "policy", "reachability"),
    ),
    "wireguard_unhealthy": TroubleshootingPlaybook(
        "wireguard_unhealthy",
        ("inventory", "interface", "routing", "firewall", "vpn", "wireguard", "diagnostic"),
        ("device_inventory", "interface_state", "routing", "policy", "reachability"),
    ),
    "vlan_reachability": TroubleshootingPlaybook(
        "vlan_reachability",
        ("inventory", "interface", "bridge", "vlan", "routing", "diagnostic"),
        ("device_inventory", "interface_state", "addressing", "routing", "reachability"),
    ),
}


def get_playbook(name: str) -> TroubleshootingPlaybook:
    key = name.strip().lower()
    try:
        return _PLAYBOOKS[key]
    except KeyError as exc:
        raise KeyError(f"unknown MikroTik troubleshooting playbook: {name}") from exc


def playbook_names() -> tuple[str, ...]:
    return tuple(sorted(_PLAYBOOKS))
