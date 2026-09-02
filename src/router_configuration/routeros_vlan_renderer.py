from __future__ import annotations

import hashlib
import ipaddress
import json
import re
from dataclasses import dataclass
from typing import Any, Mapping


class RouterOSVlanRenderError(ValueError):
    pass


_SAFE_IDENTIFIER = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.:+/-]{0,63}$")


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


def _verify_ir(ir: Mapping[str, Any]) -> str:
    if ir.get("schema_version") != "config-safe-subset-ir/1":
        raise RouterOSVlanRenderError("unsupported safe-subset IR schema")
    if ir.get("vendor_commands_present") is not False or ir.get("write_transport_present") is not False:
        raise RouterOSVlanRenderError("VLAN rendering requires command-free, transport-free IR")
    supplied = str(ir.get("ir_sha256") or "").strip()
    unsigned = dict(ir)
    unsigned.pop("ir_sha256", None)
    if not supplied or supplied != _canonical_sha256(unsigned):
        raise RouterOSVlanRenderError("safe-subset IR digest mismatch")
    return supplied


def _identifier(value: Any, label: str) -> str:
    text = str(value or "").strip()
    if not _SAFE_IDENTIFIER.fullmatch(text):
        raise RouterOSVlanRenderError(f"{label} contains unsupported RouterOS characters")
    return text


def _quote(value: str) -> str:
    return '"' + value.replace("\\", "\\\\").replace('"', '\\"').replace("$", "\\$") + '"'


def _operation(ir: Mapping[str, Any], resource: str) -> Mapping[str, Any]:
    operations = ir.get("operations")
    if not isinstance(operations, list):
        raise RouterOSVlanRenderError("safe-subset IR operations must be a list")
    matches = [
        row
        for row in operations
        if isinstance(row, Mapping) and str(row.get("resource") or "") == resource
    ]
    if len(matches) != 1:
        raise RouterOSVlanRenderError(f"VLAN renderer requires exactly one {resource} operation")
    return matches[0]


def _interface_names(state: Mapping[str, Any]) -> set[str]:
    rows = state.get("interfaces")
    if not isinstance(rows, list):
        raise RouterOSVlanRenderError("VLAN renderer requires interface discovery")
    return {
        str(row.get("name") or "").strip()
        for row in rows
        if isinstance(row, Mapping) and str(row.get("name") or "").strip()
    }


def _validate_management_path(
    management_path: Mapping[str, Any],
    interfaces: set[str],
    target_ports: set[str],
) -> str:
    if management_path.get("ok") is not True:
        raise RouterOSVlanRenderError("current management-path evidence must pass")
    current = _identifier(management_path.get("interface"), "management_path.interface")
    if current not in interfaces:
        raise RouterOSVlanRenderError("current management interface is not present in live state")
    if current in target_ports:
        raise RouterOSVlanRenderError(
            "VLAN v0.1 requires current management on an out-of-band interface not being re-bridged"
        )
    if not str(management_path.get("evidence_ref") or "").strip():
        raise RouterOSVlanRenderError("management_path.evidence_ref is required")
    return current


def _validate_clean_switching_state(
    prerequisites: Mapping[str, Any],
    *,
    bridge: str,
    ports: set[str],
    management_vlan_interface: str,
) -> None:
    if prerequisites.get("schema_version") != "routeros-render-prerequisites/1":
        raise RouterOSVlanRenderError("VLAN renderer requires routeros-render-prerequisites/1")
    switching = prerequisites.get("switching")
    if not isinstance(switching, Mapping):
        raise RouterOSVlanRenderError("VLAN renderer requires switching prerequisite state")
    for field in ("bridges", "bridge_ports", "bridge_vlans", "vlan_interfaces"):
        if not isinstance(switching.get(field), list):
            raise RouterOSVlanRenderError(f"VLAN renderer requires {field} discovery")

    if any(
        isinstance(row, Mapping) and str(row.get("name") or "").strip() == bridge
        for row in switching["bridges"]
    ):
        raise RouterOSVlanRenderError(
            "VLAN v0.1 initial-deployment renderer refuses an existing target bridge"
        )

    occupied = {
        str(row.get("interface") or "").strip()
        for row in switching["bridge_ports"]
        if isinstance(row, Mapping)
    }
    conflict = sorted(ports & occupied)
    if conflict:
        raise RouterOSVlanRenderError(
            "target VLAN ports already belong to a bridge: " + ", ".join(conflict)
        )

    if any(
        isinstance(row, Mapping)
        and str(row.get("name") or "").strip() == management_vlan_interface
        for row in switching["vlan_interfaces"]
    ):
        raise RouterOSVlanRenderError("managed management VLAN interface name already exists")


def _validate_management_address(state: Mapping[str, Any], address: str) -> None:
    try:
        target = ipaddress.ip_interface(address)
    except ValueError as exc:
        raise RouterOSVlanRenderError("management address must be an IPv4 interface CIDR") from exc
    if target.version != 4 or target.network.prefixlen == 0:
        raise RouterOSVlanRenderError("management address must be a bounded IPv4 interface CIDR")
    rows = state.get("ip_addresses")
    if not isinstance(rows, list):
        raise RouterOSVlanRenderError("VLAN renderer requires IP-address discovery")
    for row in rows:
        if not isinstance(row, Mapping):
            continue
        raw = str(row.get("address") or "").strip()
        if not raw:
            continue
        try:
            existing = ipaddress.ip_interface(raw)
        except ValueError:
            continue
        if existing.version == 4 and target.network.overlaps(existing.network):
            raise RouterOSVlanRenderError(
                f"target management network overlaps existing router address {raw!r}"
            )


@dataclass(frozen=True)
class RouterOSVlanCommand:
    command_id: str
    section: str
    command: str
    risk: int = 30

    def as_dict(self) -> dict[str, Any]:
        return {
            "command_id": self.command_id,
            "section": self.section,
            "command": self.command,
            "risk": self.risk,
        }


@dataclass(frozen=True)
class RouterOSVlanPlan:
    source_ir_sha256: str
    current_management_interface: str
    commands: tuple[RouterOSVlanCommand, ...]

    def as_dict(self) -> dict[str, Any]:
        payload = {
            "schema_version": "routeros-vlan-command-plan/1",
            "scope": "generation_only_initial_clean_deployment",
            "source_ir_sha256": self.source_ir_sha256,
            "current_management_interface": self.current_management_interface,
            "activation_policy": "management_first_vlan_filtering_last",
            "activation_last_command_id": "vlan.99.activate-filtering",
            "commands": [row.as_dict() for row in self.commands],
            "command_count": len(self.commands),
            "transport_present": False,
            "apply_available": False,
            "write_authorized": False,
        }
        payload["plan_sha256"] = _canonical_sha256(payload)
        return payload


def render_routeros_vlan(
    *,
    ir: Mapping[str, Any],
    state: Mapping[str, Any],
    prerequisites: Mapping[str, Any],
    management_path: Mapping[str, Any],
) -> RouterOSVlanPlan:
    source_sha = _verify_ir(ir)
    policy = _operation(ir, "vlan_segmentation_policy")
    attrs = policy.get("attributes")
    if not isinstance(attrs, Mapping):
        raise RouterOSVlanRenderError("vlan_segmentation_policy attributes must be an object")
    if attrs.get("activation_order") != "management_first_vlan_filtering_last":
        raise RouterOSVlanRenderError("VLAN activation order must keep vlan-filtering last")
    if attrs.get("vlan_filtering") is not True:
        raise RouterOSVlanRenderError("VLAN policy must explicitly require vlan_filtering=true")

    bridge = _identifier(attrs.get("bridge"), "VLAN bridge")
    vlans = attrs.get("vlans")
    ports = attrs.get("ports")
    management = attrs.get("management")
    if not isinstance(vlans, list) or not vlans:
        raise RouterOSVlanRenderError("VLAN renderer requires explicit VLANs")
    if not isinstance(ports, list) or not ports:
        raise RouterOSVlanRenderError("VLAN renderer requires explicit ports")
    if not isinstance(management, Mapping):
        raise RouterOSVlanRenderError("VLAN renderer requires explicit management VLAN")

    interfaces = _interface_names(state)
    port_names: set[str] = set()
    for index, port in enumerate(ports):
        if not isinstance(port, Mapping):
            raise RouterOSVlanRenderError(f"VLAN port {index} must be an object")
        interface = _identifier(port.get("interface"), f"VLAN port {index}.interface")
        if interface not in interfaces:
            raise RouterOSVlanRenderError(f"VLAN port interface {interface!r} is not present in live state")
        if interface in port_names:
            raise RouterOSVlanRenderError(f"duplicate VLAN port interface: {interface}")
        port_names.add(interface)

    management_vlan_id = management.get("vlan_id")
    if isinstance(management_vlan_id, bool) or not isinstance(management_vlan_id, int):
        raise RouterOSVlanRenderError("management VLAN id must be an integer")
    management_address = str(management.get("address") or "").strip()
    management_vlan_interface = _identifier(
        f"routercfg-mgmt-vlan{management_vlan_id}",
        "management VLAN interface",
    )

    current_management = _validate_management_path(management_path, interfaces, port_names)
    _validate_clean_switching_state(
        prerequisites,
        bridge=bridge,
        ports=port_names,
        management_vlan_interface=management_vlan_interface,
    )
    _validate_management_address(state, management_address)

    commands: list[RouterOSVlanCommand] = [
        RouterOSVlanCommand(
            "vlan.00.bridge",
            "bridge",
            f"/interface/bridge/add name={_quote(bridge)} vlan-filtering=no protocol-mode=rstp comment={_quote('routercfg:managed:vlan:bridge')}",
        )
    ]

    for index, port in enumerate(sorted(ports, key=lambda row: str(row.get("interface") or "")), start=1):
        interface = _identifier(port.get("interface"), "VLAN port interface")
        mode = str(port.get("mode") or "").strip()
        frame_types = str(port.get("frame_types") or "").strip()
        if mode not in {"access", "trunk"}:
            raise RouterOSVlanRenderError(f"VLAN port {interface!r} has unsupported mode")
        if frame_types not in {"admit-only-untagged-and-priority-tagged", "admit-only-vlan-tagged"}:
            raise RouterOSVlanRenderError(f"VLAN port {interface!r} has unsupported frame_types")
        fields = [
            f"bridge={_quote(bridge)}",
            f"interface={_quote(interface)}",
            f"frame-types={frame_types}",
            "ingress-filtering=yes",
        ]
        if mode == "access":
            pvid = port.get("access_vlan")
            if isinstance(pvid, bool) or not isinstance(pvid, int):
                raise RouterOSVlanRenderError(f"access port {interface!r} requires integer access_vlan")
            fields.append(f"pvid={pvid}")
        fields.append(f"comment={_quote(f'routercfg:managed:vlan:port:{interface}')}")
        commands.append(
            RouterOSVlanCommand(
                f"vlan.10.port.{index:03d}.{interface}",
                "bridge_port",
                "/interface/bridge/port/add " + " ".join(fields),
            )
        )

    vlan_ids: set[int] = set()
    for index, vlan in enumerate(sorted(vlans, key=lambda row: int(row.get("id", 0))), start=1):
        if not isinstance(vlan, Mapping):
            raise RouterOSVlanRenderError(f"VLAN {index} must be an object")
        vlan_id = vlan.get("id")
        if isinstance(vlan_id, bool) or not isinstance(vlan_id, int) or not 2 <= vlan_id <= 4094:
            raise RouterOSVlanRenderError("managed VLAN ids must be integers from 2 to 4094")
        if vlan_id in vlan_ids:
            raise RouterOSVlanRenderError(f"duplicate VLAN id: {vlan_id}")
        vlan_ids.add(vlan_id)
        tagged: set[str] = set()
        untagged: set[str] = set()
        if vlan_id == management_vlan_id:
            tagged.add(bridge)
        for port in ports:
            if not isinstance(port, Mapping):
                continue
            interface = str(port.get("interface") or "").strip()
            if port.get("mode") == "access" and port.get("access_vlan") == vlan_id:
                untagged.add(interface)
            if port.get("mode") == "trunk" and vlan_id in (port.get("allowed_vlans") or []):
                tagged.add(interface)
        if not tagged and not untagged:
            raise RouterOSVlanRenderError(f"VLAN {vlan_id} has no explicit bridge membership")
        fields = [f"bridge={_quote(bridge)}", f"vlan-ids={vlan_id}"]
        if tagged:
            fields.append(f"tagged={_quote(','.join(sorted(tagged)))}")
        if untagged:
            fields.append(f"untagged={_quote(','.join(sorted(untagged)))}")
        fields.append(f"comment={_quote(f'routercfg:managed:vlan:membership:{vlan_id}')}")
        commands.append(
            RouterOSVlanCommand(
                f"vlan.20.membership.{vlan_id:04d}",
                "bridge_vlan",
                "/interface/bridge/vlan/add " + " ".join(fields),
            )
        )

    if management_vlan_id not in vlan_ids:
        raise RouterOSVlanRenderError("management VLAN must exist in the VLAN membership set")
    commands.extend(
        [
            RouterOSVlanCommand(
                "vlan.30.management-interface",
                "vlan_interface",
                f"/interface/vlan/add name={_quote(management_vlan_interface)} interface={_quote(bridge)} vlan-id={management_vlan_id} comment={_quote('routercfg:managed:vlan:management-interface')}",
            ),
            RouterOSVlanCommand(
                "vlan.31.management-address",
                "ip_address",
                f"/ip/address/add address={_quote(management_address)} interface={_quote(management_vlan_interface)} comment={_quote('routercfg:managed:vlan:management-address')}",
            ),
            RouterOSVlanCommand(
                "vlan.99.activate-filtering",
                "bridge_activation",
                f"/interface/bridge/set [/interface/bridge/find where name={_quote(bridge)}] vlan-filtering=yes",
                risk=40,
            ),
        ]
    )

    return RouterOSVlanPlan(
        source_ir_sha256=source_sha,
        current_management_interface=current_management,
        commands=tuple(commands),
    )
