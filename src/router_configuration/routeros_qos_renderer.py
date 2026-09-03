from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass
from typing import Any, Mapping


class RouterOSQoSRenderError(ValueError):
    pass


QOS_OPERATION_ID = "qos.policy"
SUPPORTED_POLICY = "latency_sensitive_first"
QUEUE_TYPE = "routercfg-qos-fq"
STRATEGY = "parent_fq_codel_default_only_marked_priority_child"
LATENCY_DSCP = 46
LATENCY_PRIORITY = 1
DEFAULT_PRIORITY = 8
RESERVE_PERCENT = 10
_SAFE_IDENTIFIER = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.:+/-]{0,63}$")


def _canonical_sha256(payload: Mapping[str, Any]) -> str:
    canonical = json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
    return hashlib.sha256(canonical).hexdigest()


def _verify_ir_digest(ir: Mapping[str, Any]) -> str:
    supplied = str(ir.get("ir_sha256") or "").strip()
    if not supplied:
        raise RouterOSQoSRenderError("safe-subset IR is missing ir_sha256")
    unsigned = dict(ir)
    unsigned.pop("ir_sha256", None)
    expected = _canonical_sha256(unsigned)
    if supplied != expected:
        raise RouterOSQoSRenderError("safe-subset IR digest mismatch")
    return supplied


def _safe_identifier(value: Any, label: str) -> str:
    text = str(value or "").strip()
    if not _SAFE_IDENTIFIER.fullmatch(text):
        raise RouterOSQoSRenderError(f"{label} contains unsupported characters")
    return text


def _positive_int(value: Any, label: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value <= 0:
        raise RouterOSQoSRenderError(f"{label} must be a positive integer")
    return value


def _quote(value: str) -> str:
    return '"' + value.replace("\\", "\\\\").replace('"', '\\"').replace("$", "\\$") + '"'


def _token(name: str) -> str:
    return hashlib.sha256(name.encode("utf-8")).hexdigest()[:10]


@dataclass(frozen=True)
class RouterOSQoSCommand:
    command_id: str
    operation_id: str
    section: str
    command: str
    risk: int

    def as_dict(self) -> dict[str, Any]:
        return {"command_id": self.command_id, "operation_id": self.operation_id, "section": self.section, "command": self.command, "risk": self.risk}


@dataclass(frozen=True)
class RouterOSQoSTarget:
    name: str
    interface: str
    capacity_mbps: int
    reserve_mbps: int
    packet_mark: str
    parent_queue: str
    default_queue: str
    priority_queue: str
    comment: str

    def as_dict(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "interface": self.interface,
            "capacity_mbps": self.capacity_mbps,
            "reserve_mbps": self.reserve_mbps,
            "packet_mark": self.packet_mark,
            "parent_queue": self.parent_queue,
            "default_queue": self.default_queue,
            "priority_queue": self.priority_queue,
            "comment": self.comment,
        }


@dataclass(frozen=True)
class RouterOSQoSRenderPlan:
    source_ir_sha256: str
    policy: str
    targets: tuple[RouterOSQoSTarget, ...]
    commands: tuple[RouterOSQoSCommand, ...]

    def as_dict(self) -> dict[str, Any]:
        payload: dict[str, Any] = {
            "schema_version": "routeros-qos-command-plan/1",
            "source_ir_sha256": self.source_ir_sha256,
            "operation_id": QOS_OPERATION_ID,
            "policy": self.policy,
            "strategy": STRATEGY,
            "policy_contract": {
                "latency_dscp": LATENCY_DSCP,
                "priority": LATENCY_PRIORITY,
                "reserve_percent": RESERVE_PERCENT,
                "default_classification": "remaining_unmarked",
            },
            "queue_type": {"name": QUEUE_TYPE, "kind": "fq-codel"},
            "targets": [item.as_dict() for item in self.targets],
            "commands": [item.as_dict() for item in self.commands],
            "default_traffic_marked": False,
            "secrets_resolved": False,
            "transport_present": False,
            "apply_available": False,
            "write_authorized": False,
        }
        payload["render_sha256"] = _canonical_sha256(payload)
        return payload


def _extract_policy_and_targets(ir: Mapping[str, Any]) -> tuple[Mapping[str, Any], list[Mapping[str, Any]], str]:
    if ir.get("schema_version") != "config-safe-subset-ir/1":
        raise RouterOSQoSRenderError("unsupported safe-subset IR schema")
    if ir.get("vendor_commands_present") is not False:
        raise RouterOSQoSRenderError("source IR must not already contain vendor commands")
    if ir.get("write_transport_present") is not False:
        raise RouterOSQoSRenderError("source IR must not contain a write transport")
    source_sha = _verify_ir_digest(ir)
    operations = ir.get("operations")
    if not isinstance(operations, list):
        raise RouterOSQoSRenderError("safe-subset IR operations must be a list")
    qos_matches = [item for item in operations if isinstance(item, Mapping) and str(item.get("operation_id") or "") == QOS_OPERATION_ID and str(item.get("resource") or "") == "traffic_policy"]
    if len(qos_matches) != 1:
        raise RouterOSQoSRenderError("QoS renderer requires exactly one qos.policy traffic_policy operation")
    wan_roles = [item for item in operations if isinstance(item, Mapping) and str(item.get("resource") or "") == "wan_role"]
    if not wan_roles:
        raise RouterOSQoSRenderError("QoS renderer requires at least one compiled WAN topology role")
    return qos_matches[0], wan_roles, source_sha


def render_routeros_qos(*, ir: Mapping[str, Any]) -> RouterOSQoSRenderPlan:
    operation, wan_roles, source_sha = _extract_policy_and_targets(ir)
    attributes = operation.get("attributes")
    if not isinstance(attributes, Mapping):
        raise RouterOSQoSRenderError("qos.policy attributes must be an object")
    policy = str(attributes.get("policy") or "").strip()
    if policy != SUPPORTED_POLICY:
        raise RouterOSQoSRenderError(f"unsupported QoS policy: {policy or '<empty>'}")

    risk = int(operation.get("risk", 0))
    targets: list[RouterOSQoSTarget] = []
    seen_names: set[str] = set()
    seen_interfaces: set[str] = set()
    for index, role in enumerate(wan_roles):
        role_attributes = role.get("attributes")
        if not isinstance(role_attributes, Mapping):
            raise RouterOSQoSRenderError(f"WAN role {index} attributes must be an object")
        name = _safe_identifier(role_attributes.get("name"), f"WAN role {index}.name")
        interface = _safe_identifier(role_attributes.get("interface"), f"WAN role {index}.interface")
        capacity = _positive_int(role_attributes.get("capacity_mbps"), f"WAN role {index}.capacity_mbps")
        if name in seen_names:
            raise RouterOSQoSRenderError(f"duplicate QoS target name: {name}")
        if interface in seen_interfaces:
            raise RouterOSQoSRenderError(f"duplicate QoS target interface: {interface}")
        seen_names.add(name)
        seen_interfaces.add(interface)
        token = _token(name)
        targets.append(RouterOSQoSTarget(
            name=name,
            interface=interface,
            capacity_mbps=capacity,
            reserve_mbps=max(1, (capacity * RESERVE_PERCENT) // 100),
            packet_mark=f"routercfg-qos-{token}-ef",
            parent_queue=f"routercfg-qos-{token}-parent",
            default_queue=f"routercfg-qos-{token}-default",
            priority_queue=f"routercfg-qos-{token}-ef",
            comment=f"routercfg:managed:qos:{token}:ef",
        ))

    targets.sort(key=lambda item: item.name)
    queue_name_q = _quote(QUEUE_TYPE)
    commands: list[RouterOSQoSCommand] = [RouterOSQoSCommand(
        command_id="qos.00.queue-type.fq-codel",
        operation_id=QOS_OPERATION_ID,
        section="queue_type",
        command=f":if ([:len [/queue/type/find where name={queue_name_q}]] = 0) do={{/queue/type/add name={queue_name_q} kind=fq-codel}}",
        risk=risk,
    )]

    for index, target in enumerate(targets, start=1):
        interface_q = _quote(target.interface)
        mark_q = _quote(target.packet_mark)
        comment_q = _quote(target.comment)
        parent_q = _quote(target.parent_queue)
        default_q = _quote(target.default_queue)
        priority_q = _quote(target.priority_queue)
        max_limit = f"{target.capacity_mbps}M"
        reserve = f"{target.reserve_mbps}M"

        commands.append(RouterOSQoSCommand(
            command_id=f"qos.{index:02d}.mark-ef",
            operation_id=QOS_OPERATION_ID,
            section="firewall_mangle",
            command=(f":local rid [/ip/firewall/mangle/find where comment={comment_q}]; :if ([:len $rid] = 0) do={{/ip/firewall/mangle/add chain=forward out-interface={interface_q} dscp={LATENCY_DSCP} packet-mark=no-mark action=mark-packet new-packet-mark={mark_q} passthrough=no comment={comment_q} disabled=no}} else={{/ip/firewall/mangle/set $rid chain=forward out-interface={interface_q} dscp={LATENCY_DSCP} packet-mark=no-mark action=mark-packet new-packet-mark={mark_q} passthrough=no disabled=no}}"),
            risk=risk,
        ))
        commands.append(RouterOSQoSCommand(
            command_id=f"qos.{index:02d}.parent-default",
            operation_id=QOS_OPERATION_ID,
            section="queue_tree",
            command=(
                f":local parentRid [/queue/tree/find where name={parent_q}]; :if ([:len $parentRid] = 0) do={{/queue/tree/add name={parent_q} parent={interface_q} queue={queue_name_q} max-limit={max_limit} disabled=no}} else={{/queue/tree/set $parentRid parent={interface_q} queue={queue_name_q} max-limit={max_limit} disabled=no}}; "
                f":local defaultRid [/queue/tree/find where name={default_q}]; :if ([:len $defaultRid] = 0) do={{/queue/tree/add name={default_q} parent={parent_q} packet-mark=no-mark queue={queue_name_q} priority={DEFAULT_PRIORITY} max-limit={max_limit} disabled=no}} else={{/queue/tree/set $defaultRid parent={parent_q} packet-mark=no-mark queue={queue_name_q} priority={DEFAULT_PRIORITY} max-limit={max_limit} disabled=no}}"
            ),
            risk=risk,
        ))
        commands.append(RouterOSQoSCommand(
            command_id=f"qos.{index:02d}.priority-ef",
            operation_id=QOS_OPERATION_ID,
            section="queue_tree",
            command=(f":local rid [/queue/tree/find where name={priority_q}]; :if ([:len $rid] = 0) do={{/queue/tree/add name={priority_q} parent={parent_q} packet-mark={mark_q} queue={queue_name_q} priority={LATENCY_PRIORITY} limit-at={reserve} max-limit={max_limit} disabled=no}} else={{/queue/tree/set $rid parent={parent_q} packet-mark={mark_q} queue={queue_name_q} priority={LATENCY_PRIORITY} limit-at={reserve} max-limit={max_limit} disabled=no}}"),
            risk=risk,
        ))

    return RouterOSQoSRenderPlan(source_ir_sha256=source_sha, policy=policy, targets=tuple(targets), commands=tuple(commands))
