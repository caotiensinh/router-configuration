from __future__ import annotations

from dataclasses import dataclass
from typing import Iterable


class VirtualSwitchContractError(ValueError):
    pass


_CAPABILITIES = frozenset({"VLAN_8021Q", "PVID", "LINK_STATE", "FORWARDING"})


def _port_name(value: object) -> str:
    text = str(value or "").strip()
    if not text or any(c in text for c in ("\n", "\r", "\x00")):
        raise VirtualSwitchContractError("port name must be a non-empty safe value")
    return text


def _vlan(value: object) -> int:
    if not isinstance(value, int) or isinstance(value, bool) or not 1 <= value <= 4094:
        raise VirtualSwitchContractError("VLAN ID must be an integer from 1 through 4094")
    return value


@dataclass(frozen=True)
class VirtualSwitchPort:
    name: str
    link_up: bool
    pvid: int
    tagged_vlans: frozenset[int]
    untagged_vlans: frozenset[int]

    def as_dict(self) -> dict[str, object]:
        return {
            "name": self.name,
            "link_up": self.link_up,
            "pvid": self.pvid,
            "tagged_vlans": sorted(self.tagged_vlans),
            "untagged_vlans": sorted(self.untagged_vlans),
        }


@dataclass(frozen=True)
class ForwardDecision:
    forwarded: bool
    vlan_id: int | None
    egress_tagged: bool | None
    reason: str

    def as_dict(self) -> dict[str, object]:
        return {
            "forwarded": self.forwarded,
            "vlan_id": self.vlan_id,
            "egress_tagged": self.egress_tagged,
            "reason": self.reason,
            "evidence_class": "VIRTUAL_VERIFIED",
            "hardware_verified": False,
        }


class VirtualSwitchContract:
    def __init__(self, *, verified_capabilities: Iterable[str]) -> None:
        capabilities = frozenset(str(item).strip().upper() for item in verified_capabilities)
        unknown = capabilities - _CAPABILITIES
        if unknown:
            raise VirtualSwitchContractError(f"unknown/unverified capabilities: {sorted(unknown)}")
        self._capabilities = capabilities
        self._ports: dict[str, VirtualSwitchPort] = {}

    def _require(self, *capabilities: str) -> None:
        missing = sorted(set(capabilities) - self._capabilities)
        if missing:
            raise VirtualSwitchContractError(f"behavior requires verified capabilities: {missing}")

    def configure_port(
        self,
        *,
        name: str,
        link_up: bool,
        pvid: int,
        tagged_vlans: Iterable[int],
        untagged_vlans: Iterable[int],
    ) -> None:
        self._require("VLAN_8021Q", "PVID", "LINK_STATE")
        if type(link_up) is not bool:
            raise VirtualSwitchContractError("link_up must be boolean")
        port = _port_name(name)
        pvid_value = _vlan(pvid)
        tagged = frozenset(_vlan(item) for item in tagged_vlans)
        untagged = frozenset(_vlan(item) for item in untagged_vlans)
        if tagged & untagged:
            raise VirtualSwitchContractError("a VLAN cannot be tagged and untagged on the same port")
        if pvid_value not in untagged:
            raise VirtualSwitchContractError("PVID must be present in the port untagged VLAN set")
        self._ports[port] = VirtualSwitchPort(
            name=port,
            link_up=link_up,
            pvid=pvid_value,
            tagged_vlans=tagged,
            untagged_vlans=untagged,
        )

    def forward(self, *, ingress_port: str, egress_port: str, tagged: bool, vlan_id: int | None = None) -> ForwardDecision:
        self._require("VLAN_8021Q", "PVID", "LINK_STATE", "FORWARDING")
        ingress = self._ports.get(_port_name(ingress_port))
        egress = self._ports.get(_port_name(egress_port))
        if ingress is None or egress is None:
            raise VirtualSwitchContractError("both ingress and egress ports must be configured")
        if not ingress.link_up or not egress.link_up:
            return ForwardDecision(False, None, None, "LINK_DOWN")

        if tagged:
            if vlan_id is None:
                raise VirtualSwitchContractError("tagged ingress requires vlan_id")
            vlan = _vlan(vlan_id)
            if vlan not in ingress.tagged_vlans:
                return ForwardDecision(False, vlan, None, "INGRESS_VLAN_NOT_ADMITTED")
        else:
            if vlan_id is not None:
                raise VirtualSwitchContractError("untagged ingress must not supply vlan_id")
            vlan = ingress.pvid
            if vlan not in ingress.untagged_vlans:
                return ForwardDecision(False, vlan, None, "INGRESS_PVID_NOT_ADMITTED")

        if vlan in egress.tagged_vlans:
            return ForwardDecision(True, vlan, True, "FORWARDED_TAGGED")
        if vlan in egress.untagged_vlans:
            return ForwardDecision(True, vlan, False, "FORWARDED_UNTAGGED")
        return ForwardDecision(False, vlan, None, "EGRESS_VLAN_NOT_MEMBER")

    def snapshot(self) -> dict[str, object]:
        return {
            "schema_version": "virtual-switch-contract/1",
            "verified_capabilities": sorted(self._capabilities),
            "ports": [self._ports[name].as_dict() for name in sorted(self._ports)],
            "evidence_class": "VIRTUAL_VERIFIED",
            "hardware_verified": False,
            "production_write_authority": False,
        }
