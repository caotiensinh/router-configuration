from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any, Mapping

import diagnose_qos_flat_global as flat
import diagnose_qos_single_leaf as single
import verify_qos_packet_flow as flow
import verify_render_dry_run as base


INGRESS = "ether3"
WAN = "ether2"
GENERIC_COMMENT = "routercfg:lab:qos-debug:udp-observe"
DSCP_COMMENT = "routercfg:lab:qos-debug:dscp46-observe"
PORT_COMMENT = "routercfg:lab:qos-debug:port-classifier"
CONN_COMMENT = "routercfg:lab:qos-debug:conn-classifier"
CONN_PACKET_COMMENT = "routercfg:lab:qos-debug:conn-packet"
LAB_MARK = "routercfg-qos-debug-special"
LAB_CONN_MARK = "routercfg-qos-debug-conn"
LAB_LEAF = "routercfg-qos-debug-leaf"
LANES = {
    "dscp-observe",
    "interface-parent-forward",
    "port-classifier-global",
    "connection-mark-global",
}


def _read(path: str | Path) -> Any:
    return json.loads(Path(path).read_text(encoding="utf-8"))


def _write(path: str | Path, payload: Mapping[str, Any]) -> None:
    output = Path(path)
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def _admin(admin_url: str) -> base.LoopbackCHRAdmin:
    admin = base.LoopbackCHRAdmin(admin_url)
    admin.assert_disposable_chr()
    return admin


def _rows(admin: base.LoopbackCHRAdmin, path: str) -> list[Mapping[str, Any]]:
    _, payload = admin.request("GET", path)
    return list(base._rows(payload))


def _stats(admin: base.LoopbackCHRAdmin) -> list[Mapping[str, Any]]:
    _, payload = admin.request("POST", "queue/tree/print", {"stats": ""})
    return list(base._rows(payload))


def _one(rows: list[Mapping[str, Any]], *, key: str, value: str, label: str) -> Mapping[str, Any]:
    matches = [row for row in rows if str(row.get(key) or "") == value]
    if len(matches) != 1:
        raise flow.CHRQoSPacketFlowError(f"expected exactly one {label}, observed {len(matches)}")
    return matches[0]


def _pc(row: Mapping[str, Any], label: str) -> int:
    return flow._int_counter(row, "packets", label)


def _target(prepare: Mapping[str, Any]) -> Mapping[str, Any]:
    target = prepare.get("target")
    if not isinstance(target, Mapping):
        raise flow.CHRQoSPacketFlowError("debug lane requires production prepare target")
    if str(target.get("interface") or "") != WAN:
        raise flow.CHRQoSPacketFlowError("debug lane requires rendered ether2 WAN target")
    if not target.get("packet_mark") or not target.get("comment"):
        raise flow.CHRQoSPacketFlowError("debug lane requires production EF mark facts")
    return target


def _remove_queue_commands(target: Mapping[str, Any]) -> list[str]:
    names = set(single._remove_queue_names(target))
    names.add(LAB_LEAF)
    return [f"/queue/tree/remove [find where name={flat._quote(name)}]" for name in sorted(names) if name]


def _remove_lab_rules() -> tuple[str, ...]:
    return tuple(
        f"/ip/firewall/mangle/remove [find where comment={flat._quote(comment)}]"
        for comment in (
            GENERIC_COMMENT,
            DSCP_COMMENT,
            PORT_COMMENT,
            CONN_COMMENT,
            CONN_PACKET_COMMENT,
        )
    )


def _execute(admin: base.LoopbackCHRAdmin, commands: list[str]) -> Mapping[str, Any]:
    return flat._execute(admin, "\n".join(commands) + "\n")


def install(*, admin_url: str, prepare: Mapping[str, Any], lane: str) -> dict[str, Any]:
    if lane not in LANES:
        raise flow.CHRQoSPacketFlowError(f"unsupported debug lane: {lane}")
    admin = _admin(admin_url)
    target = _target(prepare)
    interfaces = {str(row.get("name") or "") for row in _rows(admin, "interface")}
    if not {INGRESS, WAN}.issubset(interfaces):
        raise flow.CHRQoSPacketFlowError("debug lane requires ether2 WAN and ether3 CORE")

    commands = _remove_queue_commands(target)
    commands.extend(_remove_lab_rules())

    if lane == "dscp-observe":
        commands.extend(
            (
                (
                    f"/ip/firewall/mangle/add chain=prerouting in-interface={flat._quote(INGRESS)} "
                    f"protocol=udp action=passthrough comment={flat._quote(GENERIC_COMMENT)} disabled=no"
                ),
                (
                    f"/ip/firewall/mangle/add chain=prerouting in-interface={flat._quote(INGRESS)} "
                    f"protocol=udp dscp=46 action=passthrough comment={flat._quote(DSCP_COMMENT)} disabled=no"
                ),
            )
        )
    elif lane == "interface-parent-forward":
        commands.append(
            f"/queue/tree/add name={flat._quote(LAB_LEAF)} parent={flat._quote(WAN)} "
            f"packet-mark={flat._quote(str(target['packet_mark']))} queue=default-small "
            "max-limit=100M disabled=no"
        )
    elif lane == "port-classifier-global":
        commands.extend(
            (
                (
                    f"/ip/firewall/mangle/add chain=prerouting in-interface={flat._quote(INGRESS)} "
                    f"protocol=udp src-port=46000-46079 packet-mark=no-mark action=mark-packet "
                    f"new-packet-mark={flat._quote(LAB_MARK)} passthrough=no "
                    f"comment={flat._quote(PORT_COMMENT)} disabled=no"
                ),
                (
                    f"/queue/tree/add name={flat._quote(LAB_LEAF)} parent=global "
                    f"packet-mark={flat._quote(LAB_MARK)} queue=default-small max-limit=100M disabled=no"
                ),
            )
        )
    else:
        commands.extend(
            (
                (
                    f"/ip/firewall/mangle/add chain=prerouting in-interface={flat._quote(INGRESS)} "
                    f"protocol=udp src-port=48000-48079 connection-state=new connection-mark=no-mark "
                    f"action=mark-connection new-connection-mark={flat._quote(LAB_CONN_MARK)} passthrough=yes "
                    f"comment={flat._quote(CONN_COMMENT)} disabled=no"
                ),
                (
                    f"/ip/firewall/mangle/add chain=prerouting in-interface={flat._quote(INGRESS)} "
                    f"connection-mark={flat._quote(LAB_CONN_MARK)} packet-mark=no-mark action=mark-packet "
                    f"new-packet-mark={flat._quote(LAB_MARK)} passthrough=no "
                    f"comment={flat._quote(CONN_PACKET_COMMENT)} disabled=no"
                ),
                (
                    f"/queue/tree/add name={flat._quote(LAB_LEAF)} parent=global "
                    f"packet-mark={flat._quote(LAB_MARK)} queue=default-small max-limit=100M disabled=no"
                ),
            )
        )

    result = _execute(admin, commands)
    trees = _rows(admin, "queue/tree")
    if lane != "dscp-observe":
        leaf = _one(trees, key="name", value=LAB_LEAF, label=f"{lane} leaf")
        expected_parent = WAN if lane == "interface-parent-forward" else "global"
        if str(leaf.get("parent") or "") != expected_parent:
            raise flow.CHRQoSPacketFlowError(f"{lane} leaf parent mismatch")
        if base._is_true(leaf.get("invalid")) or base._is_true(leaf.get("disabled")):
            raise flow.CHRQoSPacketFlowError(f"{lane} leaf is invalid or disabled")

    return {
        "ok": True,
        "lane": lane,
        "runtime_valid": True,
        "interface": WAN,
        "ingress_interface": INGRESS,
        "production_packet_mark": str(target["packet_mark"]),
        "production_mangle_comment": str(target["comment"]),
        "production_renderer_modified": False,
        "production_packet_flow_acceptance": False,
        "production_writer_available": False,
        "transport_exposed_to_product": False,
        "write_authorized": False,
        "physical_router_targeted": False,
        "execute": dict(result),
    }


def counters(*, admin_url: str, prepare: Mapping[str, Any], lane: str) -> dict[str, Any]:
    admin = _admin(admin_url)
    target = _target(prepare)
    mangles = _rows(admin, "ip/firewall/mangle")
    result: dict[str, Any] = {"ok": True, "lane": lane, "counter_source": "routeros_stats"}

    if lane == "dscp-observe":
        generic = _one(mangles, key="comment", value=GENERIC_COMMENT, label="generic UDP observer")
        dscp = _one(mangles, key="comment", value=DSCP_COMMENT, label="DSCP46 observer")
        result.update({"generic_udp_packets": _pc(generic, "generic_udp"), "dscp46_packets": _pc(dscp, "dscp46")})
        return result

    trees = _stats(admin)
    leaf = _one(trees, key="name", value=LAB_LEAF, label=f"{lane} queue stats")
    result["leaf_packets"] = _pc(leaf, "debug_leaf")

    if lane == "interface-parent-forward":
        prod = _one(mangles, key="comment", value=str(target["comment"]), label="production EF mangle")
        result["classifier_packets"] = _pc(prod, "production_ef")
    elif lane == "port-classifier-global":
        rule = _one(mangles, key="comment", value=PORT_COMMENT, label="port classifier")
        result["classifier_packets"] = _pc(rule, "port_classifier")
    else:
        conn = _one(mangles, key="comment", value=CONN_COMMENT, label="connection classifier")
        packet = _one(mangles, key="comment", value=CONN_PACKET_COMMENT, label="connection packet marker")
        result.update({
            "connection_classifier_packets": _pc(conn, "connection_classifier"),
            "classifier_packets": _pc(packet, "connection_packet_marker"),
        })
    return result


def evaluate(*, lane: str, before: Mapping[str, Any], after: Mapping[str, Any], flow_payload: Mapping[str, Any]) -> dict[str, Any]:
    expected_dscp = 46 if lane in {"dscp-observe", "interface-parent-forward"} else 0
    if not flow._flow_ok(flow_payload, expected_dscp=expected_dscp):
        raise flow.CHRQoSPacketFlowError(f"{lane} traffic did not traverse disposable CHR reliably")

    def delta(key: str) -> int:
        return int(after.get(key, 0)) - int(before.get(key, 0))

    evidence: dict[str, Any] = {}
    if lane == "dscp-observe":
        generic_delta = delta("generic_udp_packets")
        dscp_delta = delta("dscp46_packets")
        if generic_delta <= 0:
            raise flow.CHRQoSPacketFlowError("RouterOS prerouting generic UDP observer saw no probe packets")
        evidence = {
            "generic_udp_packet_delta": generic_delta,
            "dscp46_match_packet_delta": dscp_delta,
            "routeros_dscp46_match_observed": dscp_delta > 0,
        }
    else:
        classifier_delta = delta("classifier_packets")
        leaf_delta = delta("leaf_packets")
        if classifier_delta <= 0:
            raise flow.CHRQoSPacketFlowError(f"{lane} classifier counter did not increase")
        if leaf_delta <= 0:
            raise flow.CHRQoSPacketFlowError(f"{lane} Queue Tree leaf counter did not increase")
        evidence = {
            "classifier_packet_delta": classifier_delta,
            "leaf_packet_delta": leaf_delta,
        }
        if lane == "connection-mark-global":
            conn_delta = delta("connection_classifier_packets")
            if conn_delta <= 0:
                raise flow.CHRQoSPacketFlowError("connection-mark classifier counter did not increase")
            evidence["connection_classifier_packet_delta"] = conn_delta

    return {
        "ok": True,
        "acceptance": "PASS",
        "lane": lane,
        "scope": "disposable_chr_qos_debug_observation",
        "expected_dscp": expected_dscp,
        "requested_flows": int(flow_payload["requested_flows"]),
        "successful_flows": int(flow_payload["successful_flows"]),
        "success_ratio": float(flow_payload["success_ratio"]),
        "evidence": evidence,
        "debug_hypothesis_resolved": True,
        "production_packet_flow_acceptance": False,
        "production_renderer_modified": False,
        "aggregate_shaping_claimed": False,
        "latency_performance_claimed": False,
        "bandwidth_guarantee_claimed": False,
        "production_writer_available": False,
        "physical_router_targeted": False,
    }


def cleanup(*, admin_url: str, prepare: Mapping[str, Any]) -> dict[str, Any]:
    admin = _admin(admin_url)
    target = _target(prepare)
    commands = _remove_queue_commands(target)
    commands.extend(_remove_lab_rules())
    result = _execute(admin, commands)
    return {
        "ok": True,
        "cleanup_complete": True,
        "disposable_snapshot_required": True,
        "execute": dict(result),
    }


def main() -> int:
    parser = argparse.ArgumentParser(description="Independent disposable-CHR QoS debug lanes")
    sub = parser.add_subparsers(dest="command", required=True)
    p = sub.add_parser("install")
    p.add_argument("--admin-url", required=True)
    p.add_argument("--prepare", required=True)
    p.add_argument("--lane", choices=sorted(LANES), required=True)
    p.add_argument("--output", required=True)
    p = sub.add_parser("counters")
    p.add_argument("--admin-url", required=True)
    p.add_argument("--prepare", required=True)
    p.add_argument("--lane", choices=sorted(LANES), required=True)
    p.add_argument("--output", required=True)
    p = sub.add_parser("evaluate")
    p.add_argument("--lane", choices=sorted(LANES), required=True)
    p.add_argument("--before", required=True)
    p.add_argument("--after", required=True)
    p.add_argument("--flow", required=True)
    p.add_argument("--output", required=True)
    p = sub.add_parser("cleanup")
    p.add_argument("--admin-url", required=True)
    p.add_argument("--prepare", required=True)
    p.add_argument("--output", required=True)
    args = parser.parse_args()

    if args.command == "install":
        result = install(admin_url=args.admin_url, prepare=_read(args.prepare), lane=args.lane)
    elif args.command == "counters":
        result = counters(admin_url=args.admin_url, prepare=_read(args.prepare), lane=args.lane)
    elif args.command == "evaluate":
        result = evaluate(lane=args.lane, before=_read(args.before), after=_read(args.after), flow_payload=_read(args.flow))
    else:
        result = cleanup(admin_url=args.admin_url, prepare=_read(args.prepare))
    _write(args.output, result)
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
