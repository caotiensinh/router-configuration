from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass
from typing import Any, Mapping


class VlanIntentError(ValueError):
    pass


_NAME = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,30}$")


def _name(value: Any, label: str) -> str:
    text = str(value or "").strip()
    if not _NAME.fullmatch(text):
        raise VlanIntentError(f"{label} contains unsupported characters")
    return text


def _vlan_id(value: Any, label: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or not 2 <= value <= 4094:
        raise VlanIntentError(f"{label} must be an integer from 2 to 4094")
    return value


def _ipv4_interface(value: Any, label: str) -> str:
    try:
        interface = ipaddress.ip_interface(str(value or "").strip())
    except ValueError as exc:
        raise VlanIntentError(f"{label} must be an IPv4 interface CIDR") from exc
    if interface.version != 4 or interface.network.prefixlen == 0:
        raise VlanIntentError(f"{label} must be a bounded IPv4 interface CIDR")
    if interface.ip.is_unspecified or interface.ip.is_multicast or interface.ip.is_loopback:
        raise VlanIntentError(f"{label} must use a usable unicast IPv4 address")
    return interface.with_prefixlen


@dataclass(frozen=True)
class NormalizedVlanIntent:
    attributes: Mapping[str, Any]


def normalize_vlan_intent(segmentation: Mapping[str, Any]) -> NormalizedVlanIntent:
    if segmentation.get("enabled") is not True:
        raise VlanIntentError("VLAN segmentation intent requires enabled=true")

    required = ("bridge", "vlans", "ports", "management")
    missing = [field for field in required if field not in segmentation]
    if missing:
        raise VlanIntentError(
            "explicit VLAN segmentation is incomplete; missing: " + ", ".join(missing)
        )

    bridge = _name(segmentation.get("bridge"), "segmentation.bridge")

    raw_vlans = segmentation.get("vlans")
    if not isinstance(raw_vlans, list) or not raw_vlans:
        raise VlanIntentError("segmentation.vlans must be a non-empty list")
    vlan_ids: set[int] = set()
    vlan_names: set[str] = set()
    vlans: list[dict[str, Any]] = []
    for index, raw in enumerate(raw_vlans):
        if not isinstance(raw, Mapping):
            raise VlanIntentError(f"segmentation.vlans[{index}] must be an object")
        vid = _vlan_id(raw.get("id"), f"segmentation.vlans[{index}].id")
        name = _name(raw.get("name"), f"segmentation.vlans[{index}].name")
        if vid in vlan_ids:
            raise VlanIntentError(f"duplicate VLAN id: {vid}")
        if name in vlan_names:
            raise VlanIntentError(f"duplicate VLAN name: {name}")
        vlan_ids.add(vid)
        vlan_names.add(name)
        vlans.append({"id": vid, "name": name})
    vlans.sort(key=lambda item: int(item["id"]))

    raw_ports = segmentation.get("ports")
    if not isinstance(raw_ports, list) or not raw_ports:
        raise VlanIntentError("segmentation.ports must be a non-empty list")
    interfaces: set[str] = set()
    ports: list[dict[str, Any]] = []
    for index, raw in enumerate(raw_ports):
        if not isinstance(raw, Mapping):
            raise VlanIntentError(f"segmentation.ports[{index}] must be an object")
        interface = _name(raw.get("interface"), f"segmentation.ports[{index}].interface")
        if interface in interfaces:
            raise VlanIntentError(f"duplicate VLAN port interface: {interface}")
        interfaces.add(interface)
        mode = str(raw.get("mode") or "").strip().lower()
        if mode not in {"access", "trunk"}:
            raise VlanIntentError(f"segmentation.ports[{index}].mode must be access or trunk")

        if mode == "access":
            if "allowed_vlans" in raw:
                raise VlanIntentError("access VLAN port must not declare allowed_vlans")
            access_vlan = _vlan_id(
                raw.get("access_vlan"),
                f"segmentation.ports[{index}].access_vlan",
            )
            if access_vlan not in vlan_ids:
                raise VlanIntentError(
                    f"segmentation.ports[{index}].access_vlan references undeclared VLAN {access_vlan}"
                )
            ports.append(
                {
                    "interface": interface,
                    "mode": "access",
                    "access_vlan": access_vlan,
                    "frame_types": "admit-only-untagged-and-priority-tagged",
                    "ingress_filtering": True,
                }
            )
            continue

        if "access_vlan" in raw:
            raise VlanIntentError("trunk VLAN port must not declare access_vlan")
        allowed_raw = raw.get("allowed_vlans")
        if not isinstance(allowed_raw, list) or not allowed_raw:
            raise VlanIntentError("trunk VLAN port requires non-empty allowed_vlans")
        allowed = sorted({_vlan_id(value, f"segmentation.ports[{index}].allowed_vlans") for value in allowed_raw})
        undeclared = [value for value in allowed if value not in vlan_ids]
        if undeclared:
            raise VlanIntentError(
                "trunk VLAN port references undeclared VLANs: "
                + ", ".join(str(value) for value in undeclared)
            )
        ports.append(
            {
                "interface": interface,
                "mode": "trunk",
                "allowed_vlans": allowed,
                "frame_types": "admit-only-vlan-tagged",
                "ingress_filtering": True,
            }
        )
    ports.sort(key=lambda item: str(item["interface"]))

    management = segmentation.get("management")
    if not isinstance(management, Mapping):
        raise VlanIntentError("segmentation.management must be an object")
    management_vlan = _vlan_id(
        management.get("vlan_id"),
        "segmentation.management.vlan_id",
    )
    if management_vlan not in vlan_ids:
        raise VlanIntentError("management VLAN must be declared in segmentation.vlans")
    management_port = _name(
        management.get("port"),
        "segmentation.management.port",
    )
    management_address = _ipv4_interface(
        management.get("address"),
        "segmentation.management.address",
    )

    matching = next(
        (item for item in ports if item["interface"] == management_port),
        None,
    )
    if matching is None:
        raise VlanIntentError("management port must be declared in segmentation.ports")
    if matching["mode"] == "access" and matching["access_vlan"] != management_vlan:
        raise VlanIntentError("management access port PVID must equal the management VLAN")
    if matching["mode"] == "trunk" and management_vlan not in matching["allowed_vlans"]:
        raise VlanIntentError("management trunk port must allow the management VLAN")

    return NormalizedVlanIntent(
        attributes={
            "enabled": True,
            "bridge": bridge,
            "vlans": vlans,
            "ports": ports,
            "management": {
                "vlan_id": management_vlan,
                "port": management_port,
                "address": management_address,
            },
            "activation_order": "management_first_vlan_filtering_last",
            "vlan_filtering": True,
        }
    )
