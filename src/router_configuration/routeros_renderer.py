from __future__ import annotations

import hashlib
import ipaddress
import json
import re
from dataclasses import dataclass
from typing import Any, Mapping


class RouterOSRenderError(ValueError):
    pass


_SAFE_IDENTIFIER = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.:+/-]{0,63}$")


def _canonical_sha256(payload: Mapping[str, Any]) -> str:
    canonical = json.dumps(
        payload,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
    ).encode("utf-8")
    return hashlib.sha256(canonical).hexdigest()


def _verify_ir_digest(ir: Mapping[str, Any]) -> str:
    supplied = str(ir.get("ir_sha256") or "").strip()
    if not supplied:
        raise RouterOSRenderError("safe-subset IR is missing ir_sha256")
    unsigned = dict(ir)
    unsigned.pop("ir_sha256", None)
    expected = _canonical_sha256(unsigned)
    if supplied != expected:
        raise RouterOSRenderError("safe-subset IR digest mismatch")
    return supplied


def _safe_identifier(value: Any, label: str) -> str:
    text = str(value or "").strip()
    if not _SAFE_IDENTIFIER.fullmatch(text):
        raise RouterOSRenderError(f"{label} contains unsupported RouterOS v0.1 characters")
    return text


def _safe_ipv4(value: Any, label: str) -> str:
    text = str(value or "").strip()
    try:
        address = ipaddress.ip_address(text)
    except ValueError as exc:
        raise RouterOSRenderError(f"{label} must be an IPv4 address") from exc
    if address.version != 4 or address.is_unspecified or address.is_multicast or address.is_loopback:
        raise RouterOSRenderError(f"{label} must be a usable unicast IPv4 address")
    return str(address)


def _safe_ipv4_interface(value: Any, label: str) -> str:
    text = str(value or "").strip()
    try:
        interface = ipaddress.ip_interface(text)
    except ValueError as exc:
        raise RouterOSRenderError(f"{label} must be an IPv4 interface with prefix length") from exc
    if interface.version != 4 or interface.ip.is_unspecified or interface.ip.is_multicast or interface.ip.is_loopback:
        raise RouterOSRenderError(f"{label} must use a usable unicast IPv4 interface address")
    return str(interface)


def _safe_distance(value: Any, label: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or not 1 <= value <= 255:
        raise RouterOSRenderError(f"{label} must be an integer from 1 to 255")
    return value


def _quote(value: str) -> str:
    return '"' + value.replace("\\", "\\\\").replace('"', '\\"').replace("$", "\\$") + '"'


@dataclass(frozen=True)
class RouterOSRenderCommand:
    command_id: str
    operation_id: str
    section: str
    command: str
    risk: int

    def as_dict(self) -> dict[str, Any]:
        return {
            "command_id": self.command_id,
            "operation_id": self.operation_id,
            "section": self.section,
            "command": self.command,
            "risk": self.risk,
        }


@dataclass(frozen=True)
class RouterOSBlockedOperation:
    operation_id: str
    reason: str
    required_inputs: tuple[str, ...]

    def as_dict(self) -> dict[str, Any]:
        return {
            "operation_id": self.operation_id,
            "reason": self.reason,
            "required_inputs": list(self.required_inputs),
        }


@dataclass(frozen=True)
class RouterOSRenderPlan:
    device_id: str
    source_ir_sha256: str
    commands: tuple[RouterOSRenderCommand, ...]
    blocked_operations: tuple[RouterOSBlockedOperation, ...]
    secret_references: tuple[str, ...]

    def as_dict(self) -> dict[str, Any]:
        payload: dict[str, Any] = {
            "schema_version": "routeros-render-plan/1",
            "device_id": self.device_id,
            "source_ir_sha256": self.source_ir_sha256,
            "claim": "generation_complete" if not self.blocked_operations else "generation_partial",
            "complete": not self.blocked_operations,
            "command_format": "routeros-script/1",
            "commands": [item.as_dict() for item in self.commands],
            "blocked_operations": [item.as_dict() for item in self.blocked_operations],
            "secret_references": list(self.secret_references),
            "vendor_commands_present": bool(self.commands),
            "secrets_resolved": False,
            "transport_present": False,
            "apply_available": False,
            "write_authorized": False,
        }
        payload["render_sha256"] = _canonical_sha256(payload)
        return payload


class RouterOSSafeSubsetRenderer:
    """Generation-only RouterOS renderer for config-safe-subset-ir/1."""

    WAN_LIST = "routercfg-WAN"
    CORE_LIST = "routercfg-CORE"

    def render(self, ir: Mapping[str, Any]) -> RouterOSRenderPlan:
        if ir.get("schema_version") != "config-safe-subset-ir/1":
            raise RouterOSRenderError("unsupported safe-subset IR schema")
        if ir.get("vendor_commands_present") is not False:
            raise RouterOSRenderError("source IR must not already contain vendor commands")
        if ir.get("write_transport_present") is not False:
            raise RouterOSRenderError("source IR must not contain a write transport")

        source_sha = _verify_ir_digest(ir)
        device_id = _safe_identifier(ir.get("device_id"), "device_id")
        operations = ir.get("operations")
        if not isinstance(operations, list):
            raise RouterOSRenderError("safe-subset IR operations must be a list")

        rows: list[Mapping[str, Any]] = []
        seen_ids: set[str] = set()
        secret_references: set[str] = set()
        for raw in operations:
            if not isinstance(raw, Mapping):
                raise RouterOSRenderError("safe-subset IR contains a non-object operation")
            operation_id = _safe_identifier(raw.get("operation_id"), "operation_id")
            if operation_id in seen_ids:
                raise RouterOSRenderError(f"duplicate operation_id: {operation_id}")
            seen_ids.add(operation_id)
            rows.append(raw)
            refs = raw.get("secret_references", [])
            if not isinstance(refs, list):
                raise RouterOSRenderError(f"{operation_id}: secret_references must be a list")
            for ref in refs:
                text = str(ref or "").strip()
                if text:
                    secret_references.add(text)

        commands: list[RouterOSRenderCommand] = []
        blocked: list[RouterOSBlockedOperation] = []
        wan_list_created = False
        core_list_created = False

        for operation in sorted(rows, key=lambda item: str(item.get("operation_id") or "")):
            operation_id = str(operation["operation_id"])
            resource = str(operation.get("resource") or "")
            risk = int(operation.get("risk", 0))
            attributes = operation.get("attributes", {})
            if not isinstance(attributes, Mapping):
                raise RouterOSRenderError(f"{operation_id}: attributes must be an object")

            if resource == "wan_role":
                name = _safe_identifier(attributes.get("name"), f"{operation_id}.name")
                interface = _safe_identifier(attributes.get("interface"), f"{operation_id}.interface")
                if not wan_list_created:
                    commands.append(self._ensure_list_command(
                        command_id="interface-list.wan.ensure",
                        operation_id=operation_id,
                        list_name=self.WAN_LIST,
                        comment="routercfg:managed:wan-list",
                        risk=risk,
                    ))
                    wan_list_created = True
                commands.append(self._ensure_member_command(
                    command_id=f"interface-list.wan.member.{name}",
                    operation_id=operation_id,
                    list_name=self.WAN_LIST,
                    interface=interface,
                    comment=f"routercfg:managed:wan:{name}",
                    risk=risk,
                ))
                continue

            if resource == "core_uplink_role":
                interface = _safe_identifier(attributes.get("interface"), f"{operation_id}.interface")
                if not core_list_created:
                    commands.append(self._ensure_list_command(
                        command_id="interface-list.core.ensure",
                        operation_id=operation_id,
                        list_name=self.CORE_LIST,
                        comment="routercfg:managed:core-list",
                        risk=risk,
                    ))
                    core_list_created = True
                commands.append(self._ensure_member_command(
                    command_id="interface-list.core.member",
                    operation_id=operation_id,
                    list_name=self.CORE_LIST,
                    interface=interface,
                    comment="routercfg:managed:core-uplink",
                    risk=risk,
                ))
                continue

            if resource == "path_distribution_policy":
                rendered, blocker = self._render_multiwan_failover(operation_id, attributes, risk)
                commands.extend(rendered)
                if blocker is not None:
                    blocked.append(blocker)
                continue

            blocked.append(self._block(operation_id, resource, attributes))

        commands.sort(key=lambda item: item.command_id)
        blocked.sort(key=lambda item: item.operation_id)
        return RouterOSRenderPlan(
            device_id=device_id,
            source_ir_sha256=source_sha,
            commands=tuple(commands),
            blocked_operations=tuple(blocked),
            secret_references=tuple(sorted(secret_references)),
        )

    def _render_multiwan_failover(
        self,
        operation_id: str,
        attributes: Mapping[str, Any],
        risk: int,
    ) -> tuple[list[RouterOSRenderCommand], RouterOSBlockedOperation | None]:
        weights = attributes.get("weights")
        paths = attributes.get("paths")
        wan_names = sorted(str(name) for name in weights) if isinstance(weights, Mapping) else []
        if not wan_names or not isinstance(paths, Mapping) or set(paths) != set(wan_names):
            return [], self._block(operation_id, "path_distribution_policy", attributes)
        if not bool(attributes.get("failover", False)):
            return [], RouterOSBlockedOperation(
                operation_id,
                "capacity-weighted PCC is intentionally deferred; failover=false leaves no safe routing slice to render",
                (),
            )

        commands: list[RouterOSRenderCommand] = []
        distances: set[int] = set()
        for wan_name in wan_names:
            path = paths.get(wan_name)
            if not isinstance(path, Mapping):
                return [], self._block(operation_id, "path_distribution_policy", attributes)
            addressing = str(path.get("addressing") or "").strip().lower()
            if addressing != "static":
                return [], RouterOSBlockedOperation(
                    operation_id,
                    "recursive failover v0.1 renders only explicit static WAN addressing; dynamic gateway acquisition remains blocked",
                    (f"wan.{wan_name}.static_addressing",),
                )
            interface = _safe_identifier(path.get("interface"), f"{operation_id}.{wan_name}.interface")
            address = _safe_ipv4_interface(path.get("address"), f"{operation_id}.{wan_name}.address")
            gateway = _safe_ipv4(path.get("gateway"), f"{operation_id}.{wan_name}.gateway")
            table = _safe_identifier(path.get("table"), f"{operation_id}.{wan_name}.table")
            if table == "main":
                raise RouterOSRenderError(f"{operation_id}.{wan_name}.table must be a dedicated non-main table")
            distance = _safe_distance(
                path.get("failover_distance"), f"{operation_id}.{wan_name}.failover_distance"
            )
            if distance in distances:
                raise RouterOSRenderError("multi-WAN failover_distance values must be unique")
            distances.add(distance)
            probes_raw = path.get("health_probe_targets")
            if not isinstance(probes_raw, list) or len(probes_raw) < 2:
                raise RouterOSRenderError(f"{operation_id}.{wan_name}.health_probe_targets requires at least two targets")
            probes = [_safe_ipv4(value, f"{operation_id}.{wan_name}.health_probe_targets") for value in probes_raw]
            if len(set(probes)) != len(probes):
                raise RouterOSRenderError(f"{operation_id}.{wan_name}.health_probe_targets must be unique")

            commands.append(self._ensure_ip_address_command(
                command_id=f"address.wan.{wan_name}",
                operation_id=operation_id,
                interface=interface,
                address=address,
                comment=f"routercfg:managed:wan-address:{wan_name}",
                risk=risk,
            ))
            commands.append(self._ensure_routing_table_command(
                command_id=f"route.00.table.{wan_name}",
                operation_id=operation_id,
                table=table,
                comment=f"routercfg:managed:routing-table:{wan_name}",
                risk=risk,
            ))
            for probe_index, probe in enumerate(probes, start=1):
                probe_dst = f"{probe}/32"
                commands.append(self._ensure_route_command(
                    command_id=f"route.10.probe.{wan_name}.{probe_index}",
                    operation_id=operation_id,
                    dst_address=probe_dst,
                    gateway=gateway,
                    routing_table="main",
                    distance=1,
                    scope=10,
                    target_scope=None,
                    check_gateway=None,
                    comment=f"routercfg:managed:probe:{wan_name}:{probe_index}",
                    risk=risk,
                ))
                commands.append(self._ensure_route_command(
                    command_id=f"route.20.default.{distance:03d}.{wan_name}.{probe_index}",
                    operation_id=operation_id,
                    dst_address="0.0.0.0/0",
                    gateway=probe,
                    routing_table="main",
                    distance=distance,
                    scope=None,
                    target_scope=11,
                    check_gateway="ping",
                    comment=f"routercfg:managed:default:{wan_name}:{probe_index}",
                    risk=risk,
                ))

        blocker = RouterOSBlockedOperation(
            operation_id,
            "recursive failover is rendered; capacity-weighted PCC distribution remains intentionally blocked for the next isolated slice",
            (),
        )
        return commands, blocker

    def _ensure_list_command(self, *, command_id: str, operation_id: str, list_name: str, comment: str, risk: int) -> RouterOSRenderCommand:
        name_q = _quote(list_name)
        comment_q = _quote(comment)
        command = (
            f":if ([:len [/interface/list/find where name={name_q}]] = 0) do={{"
            f"/interface/list/add name={name_q} comment={comment_q}" "}"
        )
        return RouterOSRenderCommand(command_id, operation_id, "interface_list", command, risk)

    def _ensure_member_command(self, *, command_id: str, operation_id: str, list_name: str, interface: str, comment: str, risk: int) -> RouterOSRenderCommand:
        list_q = _quote(list_name)
        interface_q = _quote(interface)
        comment_q = _quote(comment)
        command = (
            f":local rid [/interface/list/member/find where comment={comment_q}]; "
            f":if ([:len $rid] = 0) do={{/interface/list/member/add list={list_q} "
            f"interface={interface_q} comment={comment_q}}} else={{"
            f"/interface/list/member/set $rid list={list_q} interface={interface_q}}}"
        )
        return RouterOSRenderCommand(command_id, operation_id, "interface_list_member", command, risk)

    def _ensure_ip_address_command(self, *, command_id: str, operation_id: str, interface: str, address: str, comment: str, risk: int) -> RouterOSRenderCommand:
        address_q = _quote(address)
        interface_q = _quote(interface)
        comment_q = _quote(comment)
        command = (
            f":local rid [/ip/address/find where comment={comment_q}]; "
            f":if ([:len $rid] = 0) do={{/ip/address/add address={address_q} interface={interface_q} comment={comment_q}}} "
            f"else={{/ip/address/set $rid address={address_q} interface={interface_q}}}"
        )
        return RouterOSRenderCommand(command_id, operation_id, "ip_address", command, risk)

    def _ensure_routing_table_command(self, *, command_id: str, operation_id: str, table: str, comment: str, risk: int) -> RouterOSRenderCommand:
        table_q = _quote(table)
        comment_q = _quote(comment)
        command = (
            f":local rid [/routing/table/find where name={table_q}]; "
            f":if ([:len $rid] = 0) do={{/routing/table/add fib name={table_q} comment={comment_q}}} "
            f"else={{/routing/table/set $rid fib=yes comment={comment_q}}}"
        )
        return RouterOSRenderCommand(command_id, operation_id, "routing_table", command, risk)

    def _ensure_route_command(
        self,
        *,
        command_id: str,
        operation_id: str,
        dst_address: str,
        gateway: str,
        routing_table: str,
        distance: int,
        scope: int | None,
        target_scope: int | None,
        check_gateway: str | None,
        comment: str,
        risk: int,
    ) -> RouterOSRenderCommand:
        comment_q = _quote(comment)
        fields = [
            f"dst-address={_quote(dst_address)}",
            f"gateway={_quote(gateway)}",
            f"routing-table={_quote(routing_table)}",
            f"distance={distance}",
        ]
        if scope is not None:
            fields.append(f"scope={scope}")
        if target_scope is not None:
            fields.append(f"target-scope={target_scope}")
        if check_gateway is not None:
            fields.append(f"check-gateway={check_gateway}")
        field_text = " ".join(fields)
        command = (
            f":local rid [/ip/route/find where comment={comment_q}]; "
            f":if ([:len $rid] = 0) do={{/ip/route/add {field_text} comment={comment_q}}} "
            f"else={{/ip/route/set $rid {field_text}}}"
        )
        return RouterOSRenderCommand(command_id, operation_id, "ip_route", command, risk)

    def _block(self, operation_id: str, resource: str, attributes: Mapping[str, Any]) -> RouterOSBlockedOperation:
        if resource == "path_distribution_policy":
            weights = attributes.get("weights", {})
            wan_names = sorted(str(name) for name in weights) if isinstance(weights, Mapping) else []
            required: list[str] = []
            for name in wan_names:
                required.extend((
                    f"wan.{name}.addressing_details",
                    f"wan.{name}.gateway",
                    f"wan.{name}.routing_table",
                    f"wan.{name}.failover_distance",
                    f"wan.{name}.health_probe_targets",
                ))
            return RouterOSBlockedOperation(
                operation_id,
                "weighted routing cannot be rendered until ISP addressing, gateways, failover distances and independent health probes are explicit",
                tuple(required),
            )
        if resource == "firewall_baseline":
            return RouterOSBlockedOperation(operation_id, "firewall default-deny ordering requires explicit management and required WAN-service exceptions before commands are safe", ("security.management_sources", "security.required_wan_services"))
        if resource == "wireguard_policy":
            return RouterOSBlockedOperation(operation_id, "WireGuard intent is incomplete for vendor rendering and secrets must remain unresolved during generation", ("wireguard.addresses", "wireguard.listen_port", "wireguard.peers"))
        if resource == "traffic_policy":
            return RouterOSBlockedOperation(operation_id, "QoS policy name alone is insufficient to choose safe 10G shaping and queue parameters", ("qos.classification", "qos.download_rate_mbps", "qos.upload_rate_mbps"))
        return RouterOSBlockedOperation(operation_id, f"RouterOS safe-subset renderer v0.1 does not support resource {resource!r}", ())
