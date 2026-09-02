from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass
from typing import Any, Mapping


class RouterOSQoSRenderError(ValueError):
    pass


_SAFE_IDENTIFIER = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.:+/-]{0,63}$")
_QUEUE_TYPE = "routercfg-fq-codel"
_MANAGED_PREFIX = "routercfg-qos-"


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
        raise RouterOSQoSRenderError("safe-subset IR is missing ir_sha256")
    unsigned = dict(ir)
    unsigned.pop("ir_sha256", None)
    if supplied != _canonical_sha256(unsigned):
        raise RouterOSQoSRenderError("safe-subset IR digest mismatch")
    return supplied


def _identifier(value: Any, label: str) -> str:
    text = str(value or "").strip()
    if not _SAFE_IDENTIFIER.fullmatch(text):
        raise RouterOSQoSRenderError(f"{label} contains unsupported RouterOS characters")
    return text


def _enabled(row: Mapping[str, Any]) -> bool:
    value = row.get("disabled")
    if value is True:
        return False
    return str(value).strip().lower() not in {"true", "yes", "1"}


def _quote(value: str) -> str:
    return '"' + value.replace("\\", "\\\\").replace('"', '\\"').replace("$", "\\$") + '"'


@dataclass(frozen=True)
class RouterOSQoSCommand:
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
class RouterOSQoSPlan:
    source_ir_sha256: str
    commands: tuple[RouterOSQoSCommand, ...]
    wan_interfaces: tuple[tuple[str, str], ...]

    def as_dict(self) -> dict[str, Any]:
        payload = {
            "schema_version": "routeros-qos-command-plan/1",
            "scope": "generation_only",
            "source_ir_sha256": self.source_ir_sha256,
            "classification": "existing_dscp_only",
            "default_classification": "queue_tree_packet_mark_no_mark",
            "default_mangle_generated": False,
            "queue_kind": "fq-codel",
            "queue_type_name": _QUEUE_TYPE,
            "wan_interfaces": dict(self.wan_interfaces),
            "commands": [item.as_dict() for item in self.commands],
            "command_count": len(self.commands),
            "transport_present": False,
            "apply_available": False,
            "write_authorized": False,
        }
        payload["plan_sha256"] = _canonical_sha256(payload)
        return payload


def _operation(ir: Mapping[str, Any], resource: str) -> Mapping[str, Any]:
    operations = ir.get("operations")
    if not isinstance(operations, list):
        raise RouterOSQoSRenderError("safe-subset IR operations must be a list")
    matches = [
        item
        for item in operations
        if isinstance(item, Mapping) and str(item.get("resource") or "") == resource
    ]
    if len(matches) != 1:
        raise RouterOSQoSRenderError(f"QoS renderer requires exactly one {resource} operation")
    return matches[0]


def _wan_interfaces(ir: Mapping[str, Any]) -> dict[str, str]:
    operations = ir.get("operations")
    if not isinstance(operations, list):
        raise RouterOSQoSRenderError("safe-subset IR operations must be a list")
    result: dict[str, str] = {}
    interfaces: set[str] = set()
    for item in operations:
        if not isinstance(item, Mapping) or str(item.get("resource") or "") != "wan_role":
            continue
        attrs = item.get("attributes")
        if not isinstance(attrs, Mapping):
            raise RouterOSQoSRenderError("wan_role attributes must be an object")
        name = _identifier(attrs.get("name"), "wan_role.name")
        interface = _identifier(attrs.get("interface"), f"wan_role.{name}.interface")
        if name in result or interface in interfaces:
            raise RouterOSQoSRenderError("WAN names and interfaces must be unique for QoS")
        result[name] = interface
        interfaces.add(interface)
    if not result:
        raise RouterOSQoSRenderError("QoS renderer requires at least one WAN role")
    return result


def _active_fasttrack(state: Mapping[str, Any]) -> bool:
    firewall = state.get("firewall")
    if not isinstance(firewall, Mapping):
        return False
    rows = firewall.get("filter")
    if not isinstance(rows, list):
        return False
    return any(
        isinstance(row, Mapping)
        and _enabled(row)
        and str(row.get("action") or "").strip().lower() == "fasttrack-connection"
        for row in rows
    )


def _validate_live_qos_state(state: Mapping[str, Any], wan_interfaces: Mapping[str, str]) -> None:
    qos = state.get("qos")
    if not isinstance(qos, Mapping):
        raise RouterOSQoSRenderError("QoS renderer requires discovered qos state")

    simple = qos.get("simple_queues")
    tree = qos.get("queue_tree")
    queue_types = qos.get("queue_types")
    if not isinstance(simple, list) or not isinstance(tree, list):
        raise RouterOSQoSRenderError("QoS renderer requires simple-queue and queue-tree discovery")
    if not isinstance(queue_types, list):
        raise RouterOSQoSRenderError("QoS renderer requires queue-type discovery before rendering")

    active_simple = [row for row in simple if isinstance(row, Mapping) and _enabled(row)]
    if active_simple:
        raise RouterOSQoSRenderError("active Simple Queue rules conflict with QoS v0.1 queue-tree ownership")

    wan_ifaces = set(wan_interfaces.values())
    for row in tree:
        if not isinstance(row, Mapping) or not _enabled(row):
            continue
        parent = str(row.get("parent") or "").strip()
        name = str(row.get("name") or "").strip()
        if parent in wan_ifaces and not name.startswith(_MANAGED_PREFIX):
            raise RouterOSQoSRenderError(
                f"active unmanaged Queue Tree {name!r} already owns WAN parent {parent!r}"
            )

    named = [
        row
        for row in queue_types
        if isinstance(row, Mapping) and str(row.get("name") or "").strip() == _QUEUE_TYPE
    ]
    if len(named) > 1:
        raise RouterOSQoSRenderError("managed FQ-CoDel queue type name is duplicated")
    if named and str(named[0].get("kind") or "").strip().lower() != "fq-codel":
        raise RouterOSQoSRenderError("routercfg-fq-codel exists with an incompatible queue kind")


def _ensure_queue_type() -> RouterOSQoSCommand:
    name_q = _quote(_QUEUE_TYPE)
    command = (
        f":if ([:len [/queue/type/find where name={name_q}]] = 0) do={{"
        f"/queue/type/add name={name_q} kind=fq-codel}}"
    )
    return RouterOSQoSCommand("qos.00.queue-type.fq-codel", "queue_type", command)


def _ensure_mangle(*, command_id: str, comment: str, fields: tuple[str, ...]) -> RouterOSQoSCommand:
    comment_q = _quote(comment)
    field_text = " ".join(fields)
    command = (
        f":local rid [/ip/firewall/mangle/find where comment={comment_q}]; "
        f":if ([:len $rid] = 0) do={{/ip/firewall/mangle/add {field_text} comment={comment_q}}} "
        f"else={{/ip/firewall/mangle/set $rid {field_text}}}"
    )
    return RouterOSQoSCommand(command_id, "firewall_mangle", command)


def _ensure_tree(*, command_id: str, name: str, fields: tuple[str, ...]) -> RouterOSQoSCommand:
    name_q = _quote(name)
    field_text = " ".join(fields)
    command = (
        f":local rid [/queue/tree/find where name={name_q}]; "
        f":if ([:len $rid] = 0) do={{/queue/tree/add name={name_q} {field_text}}} "
        f"else={{/queue/tree/set $rid {field_text}}}"
    )
    return RouterOSQoSCommand(command_id, "queue_tree", command)


def render_routeros_qos(*, ir: Mapping[str, Any], state: Mapping[str, Any]) -> RouterOSQoSPlan:
    if ir.get("schema_version") != "config-safe-subset-ir/1":
        raise RouterOSQoSRenderError("unsupported safe-subset IR schema")
    if ir.get("vendor_commands_present") is not False or ir.get("write_transport_present") is not False:
        raise RouterOSQoSRenderError("QoS rendering requires command-free, transport-free IR")
    source_sha = _verify_ir_digest(ir)

    policy = _operation(ir, "traffic_policy")
    attrs = policy.get("attributes")
    if not isinstance(attrs, Mapping):
        raise RouterOSQoSRenderError("traffic_policy attributes must be an object")
    required = ("egress_limits_mbps", "classes", "classification", "queue_kind")
    missing = [field for field in required if field not in attrs]
    if missing:
        raise RouterOSQoSRenderError("QoS runtime facts remain deferred; missing: " + ", ".join(missing))
    if attrs.get("classification") != "existing_dscp_only" or attrs.get("queue_kind") != "fq-codel":
        raise RouterOSQoSRenderError("QoS renderer supports only existing_dscp_only with fq-codel")

    wan_interfaces = _wan_interfaces(ir)
    limits = attrs.get("egress_limits_mbps")
    classes = attrs.get("classes")
    if not isinstance(limits, Mapping) or set(limits) != set(wan_interfaces):
        raise RouterOSQoSRenderError("QoS egress limits must cover exactly every WAN role")
    if not isinstance(classes, list) or not classes:
        raise RouterOSQoSRenderError("QoS renderer requires explicit classes")

    if _active_fasttrack(state):
        raise RouterOSQoSRenderError("active FastTrack conflicts with QoS packet marking")
    _validate_live_qos_state(state, wan_interfaces)

    commands: list[RouterOSQoSCommand] = [_ensure_queue_type()]
    for wan_name in sorted(wan_interfaces):
        interface = wan_interfaces[wan_name]
        raw_limit = limits[wan_name]
        if isinstance(raw_limit, bool) or not isinstance(raw_limit, int) or raw_limit <= 0:
            raise RouterOSQoSRenderError(f"QoS egress limit for {wan_name} must be a positive integer Mbps")
        parent_bps = raw_limit * 1_000_000
        parent_name = _identifier(f"routercfg-qos-{wan_name}", "queue parent name")
        commands.append(
            _ensure_tree(
                command_id=f"qos.20.parent.{wan_name}",
                name=parent_name,
                fields=(
                    f"parent={_quote(interface)}",
                    f"max-limit={parent_bps}",
                    "disabled=no",
                ),
            )
        )

        default_count = 0
        for index, raw_class in enumerate(classes):
            if not isinstance(raw_class, Mapping):
                raise RouterOSQoSRenderError(f"QoS class {index} must be an object")
            class_name = _identifier(raw_class.get("name"), f"QoS class {index}.name")
            priority = raw_class.get("priority")
            percent = raw_class.get("bandwidth_percent")
            if isinstance(priority, bool) or not isinstance(priority, int) or not 1 <= priority <= 8:
                raise RouterOSQoSRenderError(f"QoS class {class_name} priority must be 1..8")
            if isinstance(percent, bool) or not isinstance(percent, int) or not 1 <= percent <= 100:
                raise RouterOSQoSRenderError(f"QoS class {class_name} bandwidth_percent must be 1..100")

            leaf_name = _identifier(
                f"routercfg-qos-{wan_name}-{class_name}",
                "QoS leaf name",
            )
            is_default = raw_class.get("default") is True
            raw_dscp = raw_class.get("dscp")
            if not isinstance(raw_dscp, list):
                raise RouterOSQoSRenderError(f"QoS class {class_name} dscp must be a list")

            if is_default:
                default_count += 1
                if raw_dscp:
                    raise RouterOSQoSRenderError("default QoS class must not declare DSCP values")
                packet_mark_field = "packet-mark=no-mark"
            else:
                if not raw_dscp:
                    raise RouterOSQoSRenderError(f"QoS class {class_name} requires DSCP values")
                for dscp in sorted(set(raw_dscp)):
                    if isinstance(dscp, bool) or not isinstance(dscp, int) or not 0 <= dscp <= 63:
                        raise RouterOSQoSRenderError(f"QoS class {class_name} contains invalid DSCP")
                    commands.append(
                        _ensure_mangle(
                            command_id=f"qos.10.mark.{wan_name}.{priority:02d}.{class_name}.{dscp:02d}",
                            comment=f"routercfg:managed:qos:mark:{wan_name}:{class_name}:{dscp}",
                            fields=(
                                "chain=forward",
                                f"out-interface={_quote(interface)}",
                                f"dscp={dscp}",
                                "packet-mark=no-mark",
                                "action=mark-packet",
                                f"new-packet-mark={_quote(leaf_name)}",
                                "passthrough=no",
                                "disabled=no",
                            ),
                        )
                    )
                packet_mark_field = f"packet-mark={_quote(leaf_name)}"

            limit_at_bps = max(1, (parent_bps * percent) // 100)
            commands.append(
                _ensure_tree(
                    command_id=f"qos.30.leaf.{wan_name}.{priority:02d}.{class_name}",
                    name=leaf_name,
                    fields=(
                        f"parent={_quote(parent_name)}",
                        packet_mark_field,
                        f"queue={_quote(_QUEUE_TYPE)}",
                        f"priority={priority}",
                        f"limit-at={limit_at_bps}",
                        f"max-limit={parent_bps}",
                        "disabled=no",
                    ),
                )
            )

        if default_count != 1:
            raise RouterOSQoSRenderError("QoS renderer requires exactly one default class")

    commands.sort(key=lambda item: item.command_id)
    return RouterOSQoSPlan(
        source_ir_sha256=source_sha,
        commands=tuple(commands),
        wan_interfaces=tuple(sorted(wan_interfaces.items())),
    )
