from __future__ import annotations

import hashlib
import ipaddress
import json
import re
from dataclasses import dataclass
from typing import Any, Mapping


class RouterOSPbrRenderError(ValueError):
    pass


_SAFE_IDENTIFIER = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.:+/-]{0,63}$")
_MANAGED_COMMENT_PREFIX = "routercfg:managed:pbr:"


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
        raise RouterOSPbrRenderError("unsupported safe-subset IR schema")
    if ir.get("vendor_commands_present") is not False or ir.get("write_transport_present") is not False:
        raise RouterOSPbrRenderError("PBR rendering requires command-free, transport-free IR")
    supplied = str(ir.get("ir_sha256") or "").strip()
    unsigned = dict(ir)
    unsigned.pop("ir_sha256", None)
    if not supplied or supplied != _canonical_sha256(unsigned):
        raise RouterOSPbrRenderError("safe-subset IR digest mismatch")
    return supplied


def _identifier(value: Any, label: str) -> str:
    text = str(value or "").strip()
    if not _SAFE_IDENTIFIER.fullmatch(text):
        raise RouterOSPbrRenderError(f"{label} contains unsupported RouterOS characters")
    return text


def _cidr(value: Any, label: str, *, bounded: bool) -> str:
    try:
        network = ipaddress.ip_network(str(value or "").strip(), strict=False)
    except ValueError as exc:
        raise RouterOSPbrRenderError(f"{label} must be an IPv4 CIDR") from exc
    if network.version != 4 or (bounded and network.prefixlen == 0):
        raise RouterOSPbrRenderError(f"{label} must be a bounded IPv4 CIDR" if bounded else f"{label} must be IPv4")
    return str(network)


def _quote(value: str) -> str:
    return '"' + value.replace("\\", "\\\\").replace('"', '\\"').replace("$", "\\$") + '"'


def _operation(ir: Mapping[str, Any], resource: str, *, required: bool = True) -> Mapping[str, Any] | None:
    operations = ir.get("operations")
    if not isinstance(operations, list):
        raise RouterOSPbrRenderError("safe-subset IR operations must be a list")
    matches = [
        item
        for item in operations
        if isinstance(item, Mapping) and str(item.get("resource") or "") == resource
    ]
    if not matches and not required:
        return None
    if len(matches) != 1:
        raise RouterOSPbrRenderError(f"PBR renderer requires exactly one {resource} operation")
    return matches[0]


def _planned_tables(ir: Mapping[str, Any], state: Mapping[str, Any]) -> set[str]:
    tables = {
        str(row.get("name") or row.get("table") or "").strip()
        for row in state.get("routing_tables", [])
        if isinstance(row, Mapping)
    }
    path_policy = _operation(ir, "path_distribution_policy", required=False)
    if isinstance(path_policy, Mapping):
        attrs = path_policy.get("attributes")
        paths = attrs.get("paths") if isinstance(attrs, Mapping) else None
        if isinstance(paths, Mapping):
            for path in paths.values():
                if isinstance(path, Mapping):
                    table = str(path.get("table") or "").strip()
                    if table:
                        tables.add(table)
    tables.discard("")
    return tables


def _management_networks(ir: Mapping[str, Any]) -> tuple[ipaddress.IPv4Network, ...]:
    security = _operation(ir, "firewall_baseline", required=False)
    if not isinstance(security, Mapping):
        raise RouterOSPbrRenderError("PBR requires explicit firewall management sources")
    attrs = security.get("attributes")
    raw = attrs.get("management_sources") if isinstance(attrs, Mapping) else None
    if not isinstance(raw, list) or not raw:
        raise RouterOSPbrRenderError("PBR requires explicit firewall management sources")
    networks: list[ipaddress.IPv4Network] = []
    for value in raw:
        network = ipaddress.ip_network(str(value), strict=False)
        if network.version != 4 or network.prefixlen == 0:
            raise RouterOSPbrRenderError("management sources must be bounded IPv4 CIDRs")
        networks.append(network)
    return tuple(networks)


def _validate_prerequisites(prerequisites: Mapping[str, Any]) -> None:
    if prerequisites.get("schema_version") != "routeros-render-prerequisites/1":
        raise RouterOSPbrRenderError("PBR renderer requires routeros-render-prerequisites/1")
    policy = prerequisites.get("policy_routing")
    rules = policy.get("rules") if isinstance(policy, Mapping) else None
    if not isinstance(rules, list):
        raise RouterOSPbrRenderError("PBR renderer requires routing-rule discovery")
    unmanaged: list[str] = []
    for index, row in enumerate(rules):
        if not isinstance(row, Mapping):
            continue
        disabled = row.get("disabled")
        if disabled is True or str(disabled).strip().lower() in {"true", "yes", "1"}:
            continue
        comment = str(row.get("comment") or "").strip()
        if not comment.startswith(_MANAGED_COMMENT_PREFIX):
            unmanaged.append(str(row.get(".id") or comment or f"index:{index}"))
    if unmanaged:
        raise RouterOSPbrRenderError(
            "active unmanaged routing rules make rule precedence non-deterministic: "
            + ", ".join(unmanaged)
        )


@dataclass(frozen=True)
class RouterOSPbrCommand:
    command_id: str
    command: str
    risk: int = 30

    def as_dict(self) -> dict[str, Any]:
        return {
            "command_id": self.command_id,
            "section": "routing_rule",
            "command": self.command,
            "risk": self.risk,
        }


@dataclass(frozen=True)
class RouterOSPbrPlan:
    source_ir_sha256: str
    commands: tuple[RouterOSPbrCommand, ...]

    def as_dict(self) -> dict[str, Any]:
        payload = {
            "schema_version": "routeros-pbr-command-plan/1",
            "scope": "generation_only",
            "strategy": "routing_rules",
            "mangle_routing_marks": False,
            "source_ir_sha256": self.source_ir_sha256,
            "commands": [item.as_dict() for item in self.commands],
            "command_count": len(self.commands),
            "transport_present": False,
            "apply_available": False,
            "write_authorized": False,
        }
        payload["plan_sha256"] = _canonical_sha256(payload)
        return payload


def render_routeros_pbr(
    *,
    ir: Mapping[str, Any],
    state: Mapping[str, Any],
    prerequisites: Mapping[str, Any],
) -> RouterOSPbrPlan:
    source_sha = _verify_ir(ir)
    _validate_prerequisites(prerequisites)
    policy = _operation(ir, "policy_routing_rules")
    assert policy is not None
    attrs = policy.get("attributes")
    if not isinstance(attrs, Mapping):
        raise RouterOSPbrRenderError("policy_routing_rules attributes must be an object")
    if attrs.get("strategy") != "routing_rules" or attrs.get("mangle_routing_marks") is not False:
        raise RouterOSPbrRenderError("PBR v0.1 requires routing_rules and forbids mangle routing marks")
    rules = attrs.get("rules")
    if not isinstance(rules, list) or not rules:
        raise RouterOSPbrRenderError("PBR renderer requires explicit routing rules")

    management = _management_networks(ir)
    available_tables = _planned_tables(ir, state)
    commands: list[RouterOSPbrCommand] = []
    seen_names: set[str] = set()
    for index, raw in enumerate(rules):
        if not isinstance(raw, Mapping):
            raise RouterOSPbrRenderError(f"PBR rule {index} must be an object")
        name = _identifier(raw.get("name"), f"PBR rule {index}.name")
        if name in seen_names:
            raise RouterOSPbrRenderError(f"duplicate PBR rule name: {name}")
        seen_names.add(name)
        source = _cidr(raw.get("source_cidr"), f"PBR rule {name}.source_cidr", bounded=True)
        source_network = ipaddress.ip_network(source)
        if any(source_network.overlaps(network) for network in management):
            raise RouterOSPbrRenderError(
                f"PBR rule {name!r} overlaps a protected management source network"
            )
        destination = _cidr(
            raw.get("destination_cidr", "0.0.0.0/0"),
            f"PBR rule {name}.destination_cidr",
            bounded=False,
        )
        table = _identifier(raw.get("table"), f"PBR rule {name}.table")
        if table == "main" or table not in available_tables:
            raise RouterOSPbrRenderError(
                f"PBR rule {name!r} references routing table {table!r} that is neither live nor planned"
            )
        action = str(raw.get("action") or "lookup").strip()
        action_ros = {"lookup": "lookup", "lookup_only": "lookup-only-in-table"}.get(action)
        if action_ros is None:
            raise RouterOSPbrRenderError(f"PBR rule {name!r} uses unsupported action")
        interface_raw = raw.get("in_interface")
        interface = _identifier(interface_raw, f"PBR rule {name}.in_interface") if interface_raw else None
        comment = f"{_MANAGED_COMMENT_PREFIX}{name}"
        fields = [
            f"src-address={_quote(source)}",
            f"dst-address={_quote(destination)}",
            f"action={action_ros}",
            f"table={_quote(table)}",
        ]
        if interface:
            fields.append(f"interface={_quote(interface)}")
        fields.append("disabled=no")
        command = (
            f":local rid [/routing/rule/find where comment={_quote(comment)}]; "
            f":if ([:len $rid] = 0) do={{/routing/rule/add {' '.join(fields)} comment={_quote(comment)}}} "
            f"else={{/routing/rule/set $rid {' '.join(fields)}}}"
        )
        commands.append(RouterOSPbrCommand(f"pbr.{index + 1:03d}.{name}", command))

    return RouterOSPbrPlan(source_ir_sha256=source_sha, commands=tuple(commands))
