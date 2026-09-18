from __future__ import annotations

import ipaddress
from dataclasses import dataclass
from typing import Iterable


class VirtualGatewayContractError(ValueError):
    pass


_CAPABILITIES = frozenset({"INTERFACES", "STATIC_ROUTING", "FORWARDING", "FIREWALL"})


@dataclass(frozen=True)
class GatewayInterface:
    name: str
    network: ipaddress.IPv4Network
    address: ipaddress.IPv4Address
    role: str


@dataclass(frozen=True)
class StaticRoute:
    destination: ipaddress.IPv4Network
    next_hop: ipaddress.IPv4Address
    metric: int


@dataclass(frozen=True)
class ForwardDecision:
    forwarded: bool
    egress_interface: str | None
    next_hop: str | None
    reason: str

    def as_dict(self) -> dict[str, object]:
        return {
            "forwarded": self.forwarded,
            "egress_interface": self.egress_interface,
            "next_hop": self.next_hop,
            "reason": self.reason,
            "evidence_class": "VIRTUAL_VERIFIED",
            "hardware_verified": False,
        }


class VirtualGatewayContract:
    def __init__(self, *, verified_capabilities: Iterable[str]) -> None:
        capabilities = frozenset(str(item).strip().upper() for item in verified_capabilities)
        unknown = capabilities - _CAPABILITIES
        if unknown:
            raise VirtualGatewayContractError(f"unknown/unverified capabilities: {sorted(unknown)}")
        self._capabilities = capabilities
        self._interfaces: dict[str, GatewayInterface] = {}
        self._routes: list[StaticRoute] = []
        self._blocked_destinations: set[ipaddress.IPv4Network] = set()

    def _require(self, *capabilities: str) -> None:
        missing = sorted(set(capabilities) - self._capabilities)
        if missing:
            raise VirtualGatewayContractError(f"behavior requires verified capabilities: {missing}")

    def add_interface(self, *, name: str, cidr: str, role: str) -> None:
        self._require("INTERFACES")
        interface = ipaddress.IPv4Interface(cidr)
        key = str(name or "").strip()
        normalized_role = str(role or "").strip().upper()
        if not key or normalized_role not in {"LAN", "WAN"}:
            raise VirtualGatewayContractError("interface requires name and LAN/WAN role")
        if key in self._interfaces:
            raise VirtualGatewayContractError("duplicate interface")
        for existing in self._interfaces.values():
            if interface.network.overlaps(existing.network):
                raise VirtualGatewayContractError("interface networks must not overlap")
        self._interfaces[key] = GatewayInterface(key, interface.network, interface.ip, normalized_role)

    def add_static_route(self, *, destination: str, next_hop: str, metric: int = 1) -> None:
        self._require("STATIC_ROUTING")
        network = ipaddress.IPv4Network(destination, strict=False)
        hop = ipaddress.IPv4Address(next_hop)
        if not isinstance(metric, int) or isinstance(metric, bool) or metric < 1:
            raise VirtualGatewayContractError("metric must be a positive integer")
        if not any(hop in interface.network for interface in self._interfaces.values()):
            raise VirtualGatewayContractError("next_hop must be reachable through a configured interface")
        self._routes.append(StaticRoute(network, hop, metric))

    def block_destination(self, cidr: str) -> None:
        self._require("FIREWALL")
        self._blocked_destinations.add(ipaddress.IPv4Network(cidr, strict=False))

    def forward(self, destination: str) -> ForwardDecision:
        self._require("INTERFACES", "FORWARDING")
        target = ipaddress.IPv4Address(destination)
        if "FIREWALL" in self._capabilities and any(target in network for network in self._blocked_destinations):
            return ForwardDecision(False, None, None, "FIREWALL_BLOCK")

        connected = [interface for interface in self._interfaces.values() if target in interface.network]
        if connected:
            interface = sorted(connected, key=lambda item: item.name)[0]
            return ForwardDecision(True, interface.name, None, "CONNECTED_ROUTE")

        if "STATIC_ROUTING" not in self._capabilities:
            return ForwardDecision(False, None, None, "NO_ROUTE")

        matches = [route for route in self._routes if target in route.destination]
        if not matches:
            return ForwardDecision(False, None, None, "NO_ROUTE")
        route = sorted(matches, key=lambda item: (-item.destination.prefixlen, item.metric, str(item.next_hop)))[0]
        egress = [interface for interface in self._interfaces.values() if route.next_hop in interface.network]
        if not egress:
            return ForwardDecision(False, None, None, "NEXT_HOP_UNREACHABLE")
        interface = sorted(egress, key=lambda item: item.name)[0]
        return ForwardDecision(True, interface.name, str(route.next_hop), "STATIC_ROUTE")

    def snapshot(self) -> dict[str, object]:
        return {
            "schema_version": "virtual-gateway-contract/1",
            "verified_capabilities": sorted(self._capabilities),
            "interfaces": [
                {"name": i.name, "network": str(i.network), "address": str(i.address), "role": i.role}
                for i in sorted(self._interfaces.values(), key=lambda item: item.name)
            ],
            "routes": [
                {"destination": str(r.destination), "next_hop": str(r.next_hop), "metric": r.metric}
                for r in sorted(self._routes, key=lambda item: (str(item.destination), item.metric, str(item.next_hop)))
            ],
            "blocked_destinations": sorted(str(network) for network in self._blocked_destinations),
            "evidence_class": "VIRTUAL_VERIFIED",
            "hardware_verified": False,
            "production_write_authority": False,
        }
