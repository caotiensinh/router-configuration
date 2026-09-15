from __future__ import annotations

import hashlib
import ipaddress
import json
from dataclasses import dataclass
from enum import Enum
from typing import Any

from router_configuration.test_harness import CommonScenario


class LabPortRole(str, Enum):
    MANAGEMENT = "management"
    WAN_PRIMARY = "wan_primary"
    WAN_BACKUP = "wan_backup"
    LAN = "lan"


class FaultPlane(str, Enum):
    EXTERNAL_NETWORK = "external_network"
    SERVICE = "service"
    VENDOR_CONTROL_PLANE = "vendor_control_plane"


class FaultAction(str, Enum):
    UPSTREAM_PACKET_BLACKHOLE = "upstream_packet_blackhole"
    DNS_RESPONDER_STOP = "dns_responder_stop"
    DISABLE_OWNED_DEFAULT_ROUTE = "disable_owned_default_route"


@dataclass(frozen=True)
class LabAttachment:
    role: LabPortRole
    guest_order: int
    network: str | None
    dut_address: str | None
    harness_address: str | None
    addressing_mode: str = "static"

    def as_dict(self) -> dict[str, Any]:
        return {
            "role": self.role.value,
            "guest_order": self.guest_order,
            "network": self.network,
            "dut_address": self.dut_address,
            "harness_address": self.harness_address,
            "addressing_mode": self.addressing_mode,
        }


@dataclass(frozen=True)
class StandardLabTopology:
    attachments: tuple[LabAttachment, ...]
    service_ip: str
    dns_ip: str

    @classmethod
    def build(cls) -> "StandardLabTopology":
        topology = cls(
            attachments=(
                LabAttachment(
                    LabPortRole.MANAGEMENT,
                    0,
                    None,
                    None,
                    None,
                    "adapter_defined_isolated",
                ),
                LabAttachment(
                    LabPortRole.WAN_PRIMARY,
                    1,
                    "192.0.2.0/30",
                    "192.0.2.2",
                    "192.0.2.1",
                ),
                LabAttachment(
                    LabPortRole.WAN_BACKUP,
                    2,
                    "198.51.100.0/30",
                    "198.51.100.2",
                    "198.51.100.1",
                ),
                LabAttachment(
                    LabPortRole.LAN,
                    3,
                    "10.10.10.0/24",
                    "10.10.10.1",
                    "10.10.10.2",
                ),
            ),
            service_ip="203.0.113.100",
            dns_ip="203.0.113.53",
        )
        topology.validate()
        return topology

    def validate(self) -> None:
        roles = [item.role for item in self.attachments]
        required = set(LabPortRole)
        if set(roles) != required or len(roles) != len(required):
            raise ValueError("standard lab topology requires exactly one attachment per port role")
        orders = [item.guest_order for item in self.attachments]
        if len(set(orders)) != len(orders) or sorted(orders) != [0, 1, 2, 3]:
            raise ValueError("standard lab guest_order must be unique and cover 0..3")

        networks: list[ipaddress.IPv4Network] = []
        for item in self.attachments:
            if item.role is LabPortRole.MANAGEMENT:
                if item.addressing_mode != "adapter_defined_isolated":
                    raise ValueError("management attachment must remain adapter-defined and isolated")
                if any(value is not None for value in (item.network, item.dut_address, item.harness_address)):
                    raise ValueError("common topology must not invent vendor management addressing")
                continue
            if item.addressing_mode != "static":
                raise ValueError(f"{item.role.value} must use static lab addressing")
            if not item.network or not item.dut_address or not item.harness_address:
                raise ValueError(f"{item.role.value} requires network, DUT and harness addresses")
            network = ipaddress.ip_network(item.network, strict=True)
            dut = ipaddress.ip_address(item.dut_address)
            harness = ipaddress.ip_address(item.harness_address)
            if dut not in network or harness not in network or dut == harness:
                raise ValueError(f"{item.role.value} addresses must be distinct members of its network")
            networks.append(network)

        for index, left in enumerate(networks):
            for right in networks[index + 1 :]:
                if left.overlaps(right):
                    raise ValueError("standard lab data networks must not overlap")

        service = ipaddress.ip_address(self.service_ip)
        dns = ipaddress.ip_address(self.dns_ip)
        if service == dns:
            raise ValueError("service_ip and dns_ip must be distinct")
        if any(service in network or dns in network for network in networks):
            raise ValueError("service and DNS endpoints must stay outside DUT transit/LAN networks")

    def as_dict(self) -> dict[str, Any]:
        payload = {
            "schema_version": "network-device-standard-lab-topology/1",
            "attachments": [item.as_dict() for item in self.attachments],
            "service_ip": self.service_ip,
            "dns_ip": self.dns_ip,
            "management_isolated": True,
            "vendor_management_addressing": "adapter_defined",
            "physical_hardware_claimed": False,
            "production_writer_available": False,
            "write_authorized": False,
        }
        encoded = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")
        payload["topology_sha256"] = hashlib.sha256(encoded).hexdigest()
        return payload


@dataclass(frozen=True)
class CommonFaultPlan:
    scenario: CommonScenario
    plane: FaultPlane
    action: FaultAction
    target_role: LabPortRole
    reusable_across_vendors: bool
    requires_vendor_adapter: bool

    def as_dict(self) -> dict[str, Any]:
        return {
            "schema_version": "network-device-common-fault-plan/1",
            "scenario": self.scenario.value,
            "plane": self.plane.value,
            "action": self.action.value,
            "target_role": self.target_role.value,
            "reusable_across_vendors": self.reusable_across_vendors,
            "requires_vendor_adapter": self.requires_vendor_adapter,
            "production_writer_available": False,
            "write_authorized": False,
        }


_FAULT_PLANS = {
    CommonScenario.WAN_FAILOVER: CommonFaultPlan(
        CommonScenario.WAN_FAILOVER,
        FaultPlane.EXTERNAL_NETWORK,
        FaultAction.UPSTREAM_PACKET_BLACKHOLE,
        LabPortRole.WAN_PRIMARY,
        True,
        False,
    ),
    CommonScenario.DNS_FAILURE: CommonFaultPlan(
        CommonScenario.DNS_FAILURE,
        FaultPlane.SERVICE,
        FaultAction.DNS_RESPONDER_STOP,
        LabPortRole.WAN_PRIMARY,
        True,
        False,
    ),
    CommonScenario.DEFAULT_ROUTE_LOSS: CommonFaultPlan(
        CommonScenario.DEFAULT_ROUTE_LOSS,
        FaultPlane.VENDOR_CONTROL_PLANE,
        FaultAction.DISABLE_OWNED_DEFAULT_ROUTE,
        LabPortRole.WAN_PRIMARY,
        False,
        True,
    ),
}


def plan_common_fault(scenario: CommonScenario | str) -> CommonFaultPlan:
    item = scenario if isinstance(scenario, CommonScenario) else CommonScenario(str(scenario))
    try:
        return _FAULT_PLANS[item]
    except KeyError as exc:
        raise ValueError(f"no common fault plan is defined for {item.value}") from exc
