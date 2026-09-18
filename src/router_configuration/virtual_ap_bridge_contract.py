from __future__ import annotations

from dataclasses import dataclass
from typing import Iterable


class VirtualApBridgeError(ValueError):
    pass


_AP_CAPABILITIES = frozenset({"SSID", "RADIO_STATE", "CLIENT_ASSOCIATION", "VLAN_MAPPING"})
_BRIDGE_CAPABILITIES = frozenset({"BRIDGE_FORWARDING", "VLAN_8021Q", "LINK_STATE"})


def _safe(value: object, label: str) -> str:
    text = str(value or "").strip()
    if not text or any(ch in text for ch in ("\n", "\r", "\x00")):
        raise VirtualApBridgeError(f"{label} must be a non-empty single-line value")
    return text


def _vlan(value: object) -> int:
    if not isinstance(value, int) or isinstance(value, bool) or not 1 <= value <= 4094:
        raise VirtualApBridgeError("VLAN ID must be from 1 through 4094")
    return value


@dataclass(frozen=True)
class ClientAssociation:
    client_id: str
    ssid: str
    vlan_id: int


class VirtualAP:
    def __init__(self, *, verified_capabilities: Iterable[str]) -> None:
        capabilities = frozenset(str(item).strip().upper() for item in verified_capabilities)
        unknown = capabilities - _AP_CAPABILITIES
        if unknown:
            raise VirtualApBridgeError(f"unknown/unverified AP capabilities: {sorted(unknown)}")
        self._capabilities = capabilities
        self._radio_up = False
        self._ssids: dict[str, int] = {}
        self._clients: dict[str, ClientAssociation] = {}

    def _require(self, *caps: str) -> None:
        missing = sorted(set(caps) - self._capabilities)
        if missing:
            raise VirtualApBridgeError(f"AP behavior requires verified capabilities: {missing}")

    def set_radio(self, up: bool) -> None:
        self._require("RADIO_STATE")
        if type(up) is not bool:
            raise VirtualApBridgeError("radio state must be boolean")
        self._radio_up = up

    def add_ssid(self, *, ssid: str, vlan_id: int) -> None:
        self._require("SSID", "VLAN_MAPPING")
        name = _safe(ssid, "ssid")
        if name in self._ssids:
            raise VirtualApBridgeError("duplicate SSID")
        self._ssids[name] = _vlan(vlan_id)

    def associate(self, *, client_id: str, ssid: str) -> ClientAssociation:
        self._require("SSID", "RADIO_STATE", "CLIENT_ASSOCIATION", "VLAN_MAPPING")
        if not self._radio_up:
            raise VirtualApBridgeError("radio is down")
        client = _safe(client_id, "client_id")
        name = _safe(ssid, "ssid")
        if name not in self._ssids:
            raise VirtualApBridgeError("SSID is not configured")
        association = ClientAssociation(client, name, self._ssids[name])
        self._clients[client] = association
        return association

    def snapshot(self) -> dict[str, object]:
        return {
            "schema_version": "virtual-ap-contract/1",
            "verified_capabilities": sorted(self._capabilities),
            "radio_up": self._radio_up,
            "ssids": [{"ssid": name, "vlan_id": self._ssids[name]} for name in sorted(self._ssids)],
            "clients": [
                {"client_id": item.client_id, "ssid": item.ssid, "vlan_id": item.vlan_id}
                for item in sorted(self._clients.values(), key=lambda row: row.client_id)
            ],
            "evidence_class": "VIRTUAL_VERIFIED",
            "hardware_verified": False,
            "production_write_authority": False,
        }


class VirtualBridge:
    def __init__(self, *, verified_capabilities: Iterable[str]) -> None:
        capabilities = frozenset(str(item).strip().upper() for item in verified_capabilities)
        unknown = capabilities - _BRIDGE_CAPABILITIES
        if unknown:
            raise VirtualApBridgeError(f"unknown/unverified bridge capabilities: {sorted(unknown)}")
        self._capabilities = capabilities
        self._ports: dict[str, tuple[bool, frozenset[int]]] = {}

    def _require(self, *caps: str) -> None:
        missing = sorted(set(caps) - self._capabilities)
        if missing:
            raise VirtualApBridgeError(f"bridge behavior requires verified capabilities: {missing}")

    def add_port(self, *, name: str, link_up: bool, vlans: Iterable[int]) -> None:
        self._require("LINK_STATE", "VLAN_8021Q")
        port = _safe(name, "port")
        if port in self._ports:
            raise VirtualApBridgeError("duplicate bridge port")
        if type(link_up) is not bool:
            raise VirtualApBridgeError("link_up must be boolean")
        allowed = frozenset(_vlan(vlan) for vlan in vlans)
        if not allowed:
            raise VirtualApBridgeError("bridge port must admit at least one VLAN")
        self._ports[port] = (link_up, allowed)

    def forward(self, *, ingress_port: str, egress_port: str, vlan_id: int) -> dict[str, object]:
        self._require("BRIDGE_FORWARDING", "VLAN_8021Q", "LINK_STATE")
        ingress = self._ports.get(_safe(ingress_port, "ingress_port"))
        egress = self._ports.get(_safe(egress_port, "egress_port"))
        if ingress is None or egress is None:
            raise VirtualApBridgeError("both bridge ports must exist")
        vlan = _vlan(vlan_id)
        if not ingress[0] or not egress[0]:
            forwarded, reason = False, "LINK_DOWN"
        elif vlan not in ingress[1]:
            forwarded, reason = False, "INGRESS_VLAN_NOT_ADMITTED"
        elif vlan not in egress[1]:
            forwarded, reason = False, "EGRESS_VLAN_NOT_ADMITTED"
        else:
            forwarded, reason = True, "FORWARDED"
        return {
            "forwarded": forwarded,
            "vlan_id": vlan,
            "reason": reason,
            "evidence_class": "VIRTUAL_VERIFIED",
            "hardware_verified": False,
        }

    def snapshot(self) -> dict[str, object]:
        return {
            "schema_version": "virtual-bridge-contract/1",
            "verified_capabilities": sorted(self._capabilities),
            "ports": [
                {"name": name, "link_up": state[0], "vlans": sorted(state[1])}
                for name, state in sorted(self._ports.items())
            ],
            "evidence_class": "VIRTUAL_VERIFIED",
            "hardware_verified": False,
            "production_write_authority": False,
        }
