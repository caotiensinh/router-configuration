from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass
from typing import Any, Mapping

from .routeros_pcc_plan import RouterOSPccRenderSpec, assess_routeros_pcc


class RouterOSPccRenderError(ValueError):
    pass


_SAFE_IDENTIFIER = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.:+/-]{0,63}$")


def _quote(value: str) -> str:
    return '"' + value.replace("\\", "\\\\").replace('"', '\\"').replace("$", "\\$") + '"'


def _safe_identifier(value: Any, label: str) -> str:
    text = str(value or "").strip()
    if not _SAFE_IDENTIFIER.fullmatch(text):
        raise RouterOSPccRenderError(f"{label} contains unsupported RouterOS characters")
    return text


def _safe_ipv4(value: Any, label: str) -> str:
    text = str(value or "").strip()
    try:
        address = ipaddress.ip_address(text)
    except ValueError as exc:
        raise RouterOSPccRenderError(f"{label} must be an IPv4 address") from exc
    if address.version != 4 or address.is_unspecified or address.is_multicast or address.is_loopback:
        raise RouterOSPccRenderError(f"{label} must be a usable unicast IPv4 address")
    return str(address)


@dataclass(frozen=True)
class RouterOSPccCommand:
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
class RouterOSPccCommandPlan:
    spec: RouterOSPccRenderSpec
    commands: tuple[RouterOSPccCommand, ...]

    def as_dict(self) -> dict[str, Any]:
        return {
            "schema_version": "routeros-pcc-command-plan/1",
            "scope": "generation_only",
            "pcc_spec": self.spec.as_dict(),
            "commands": [command.as_dict() for command in self.commands],
            "command_count": len(self.commands),
            "transport_present": False,
            "apply_available": False,
            "write_authorized": False,
        }


def _path_attributes(ir: Mapping[str, Any]) -> dict[str, dict[str, Any]]:
    operations = ir.get("operations", [])
    if not isinstance(operations, list):
        raise RouterOSPccRenderError("safe-subset IR operations must be a list")
    candidates = [
        operation
        for operation in operations
        if isinstance(operation, Mapping)
        and str(operation.get("resource") or "") == "path_distribution_policy"
    ]
    if len(candidates) != 1:
        raise RouterOSPccRenderError("PCC renderer requires exactly one path_distribution_policy")
    attributes = candidates[0].get("attributes", {})
    if not isinstance(attributes, Mapping):
        raise RouterOSPccRenderError("path_distribution_policy attributes must be an object")
    paths = attributes.get("paths")
    if not isinstance(paths, Mapping):
        raise RouterOSPccRenderError("PCC renderer requires explicit WAN paths")

    result: dict[str, dict[str, Any]] = {}
    for wan_name, raw in paths.items():
        name = _safe_identifier(wan_name, "wan_name")
        if not isinstance(raw, Mapping):
            raise RouterOSPccRenderError(f"PCC path {name!r} must be an object")
        table = _safe_identifier(raw.get("table"), f"{name}.table")
        distance = raw.get("failover_distance")
        if isinstance(distance, bool) or not isinstance(distance, int) or not 1 <= distance <= 255:
            raise RouterOSPccRenderError(f"{name}.failover_distance must be an integer from 1 to 255")
        probes_raw = raw.get("health_probe_targets")
        if not isinstance(probes_raw, list) or len(probes_raw) < 2:
            raise RouterOSPccRenderError(f"{name}.health_probe_targets requires at least two targets")
        probes = tuple(_safe_ipv4(value, f"{name}.health_probe_targets") for value in probes_raw)
        if len(set(probes)) != len(probes):
            raise RouterOSPccRenderError(f"{name}.health_probe_targets must be unique")
        result[name] = {
            "table": table,
            "failover_distance": distance,
            "probes": probes,
        }
    return result


def _connection_mark(wan_name: str) -> str:
    mark = f"routercfg-pcc-{wan_name}"
    return _safe_identifier(mark, f"connection mark for {wan_name}")


def _ensure_mangle_command(
    *,
    command_id: str,
    comment: str,
    fields: tuple[str, ...],
) -> RouterOSPccCommand:
    comment_q = _quote(comment)
    field_text = " ".join(fields)
    command = (
        f":local rid [/ip/firewall/mangle/find where comment={comment_q}]; "
        f":if ([:len $rid] = 0) do={{/ip/firewall/mangle/add {field_text} comment={comment_q}}} "
        f"else={{/ip/firewall/mangle/set $rid {field_text}}}"
    )
    return RouterOSPccCommand(command_id, "firewall_mangle", command)


def _ensure_policy_route_command(
    *,
    command_id: str,
    comment: str,
    routing_table: str,
    gateway_probe: str,
    distance: int,
) -> RouterOSPccCommand:
    comment_q = _quote(comment)
    fields = " ".join(
        (
            'dst-address="0.0.0.0/0"',
            f"gateway={_quote(gateway_probe + '@main')}",
            f"routing-table={_quote(routing_table)}",
            f"distance={distance}",
            "target-scope=11",
            "check-gateway=ping",
        )
    )
    command = (
        f":local rid [/ip/route/find where comment={comment_q}]; "
        f":if ([:len $rid] = 0) do={{/ip/route/add {fields} comment={comment_q}}} "
        f"else={{/ip/route/set $rid {fields}}}"
    )
    return RouterOSPccCommand(command_id, "pcc_policy_route", command)


def render_routeros_pcc(
    *,
    ir: Mapping[str, Any],
    state: Mapping[str, Any],
    max_buckets: int = 64,
) -> RouterOSPccCommandPlan:
    """Render an isolated, generation-only outbound PCC command plan.

    The caller must place these commands after the recursive failover/table
    commands. No transport or apply capability exists here. Active FastTrack or
    dstnat causes planning to fail before command generation.
    """

    assessment = assess_routeros_pcc(ir=ir, state=state, max_buckets=max_buckets)
    if not assessment.ok or assessment.spec is None:
        raise RouterOSPccRenderError("; ".join(assessment.errors) or "PCC assessment failed")
    spec = assessment.spec
    if spec.scope != "outbound_core_only":
        raise RouterOSPccRenderError("unsupported PCC scope")
    if not spec.exclude_local_destinations:
        raise RouterOSPccRenderError("PCC renderer requires local-destination exclusion")
    if spec.connection_state != "new" or not spec.require_unmarked_connection:
        raise RouterOSPccRenderError("PCC renderer requires new, previously unmarked connection classification")
    if spec.fasttrack_compatible:
        raise RouterOSPccRenderError("PCC renderer must not claim FastTrack compatibility")

    paths = _path_attributes(ir)
    if set(paths) != {name for name, _ in spec.routing_tables}:
        raise RouterOSPccRenderError("PCC spec/path WAN set mismatch")

    commands: list[RouterOSPccCommand] = []

    # Every policy table gets its assigned WAN first and all other WANs as
    # deterministic fallbacks ordered by operator failover distance. These
    # routes intentionally come before any mangle rule so a future apply path
    # never marks traffic toward an empty policy table.
    for target_wan, target_table in spec.routing_tables:
        alternatives = [name for name in paths if name != target_wan]
        alternatives.sort(key=lambda name: (int(paths[name]["failover_distance"]), name))
        ordered = [target_wan, *alternatives]
        for rank, path_wan in enumerate(ordered, start=1):
            probes = paths[path_wan]["probes"]
            for probe_index, probe in enumerate(probes, start=1):
                comment = f"routercfg:managed:pcc-route:{target_wan}:{path_wan}:{probe_index}"
                commands.append(
                    _ensure_policy_route_command(
                        command_id=f"pcc.route.{target_wan}.{rank:03d}.{path_wan}.{probe_index}",
                        comment=comment,
                        routing_table=target_table,
                        gateway_probe=probe,
                        distance=rank,
                    )
                )

    # PCC connection classification is exact: one rule per reduced-ratio bucket.
    for bucket in spec.buckets:
        mark = _connection_mark(bucket.wan_name)
        comment = f"routercfg:managed:pcc-connection:{bucket.wan_name}:{bucket.remainder}"
        commands.append(
            _ensure_mangle_command(
                command_id=f"pcc.mangle.connection.{bucket.remainder:03d}.{bucket.wan_name}",
                comment=comment,
                fields=(
                    "chain=prerouting",
                    "action=mark-connection",
                    "connection-state=new",
                    "connection-mark=no-mark",
                    "dst-address-type=!local",
                    f"in-interface-list={_quote(spec.ingress_interface_list)}",
                    f"new-connection-mark={_quote(mark)}",
                    f"per-connection-classifier={_quote(spec.classifier + ':' + bucket.classifier)}",
                    "passthrough=yes",
                ),
            )
        )

    # All packets of an already classified connection inherit its WAN table.
    # Routing marks remain after the connection classifiers so the connection
    # mark exists before the routing mark is evaluated.
    for wan_name, table in spec.routing_tables:
        mark = _connection_mark(wan_name)
        comment = f"routercfg:managed:pcc-routing:{wan_name}"
        commands.append(
            _ensure_mangle_command(
                command_id=f"pcc.mangle.routing.{wan_name}",
                comment=comment,
                fields=(
                    "chain=prerouting",
                    "action=mark-routing",
                    f"connection-mark={_quote(mark)}",
                    "dst-address-type=!local",
                    f"in-interface-list={_quote(spec.ingress_interface_list)}",
                    f"new-routing-mark={_quote(table)}",
                    "passthrough=no",
                ),
            )
        )

    return RouterOSPccCommandPlan(spec=spec, commands=tuple(commands))
