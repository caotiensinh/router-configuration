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
LAB_MARK = "routercfg-qos-hdbg-special"
LAB_MARK_COMMENT = "routercfg:lab:qos-hdbg:special"
LAB_PARENT = "routercfg-qos-hdbg-parent"
LAB_CHILD = "routercfg-qos-hdbg-child"
LAB_LEAF = "routercfg-qos-hdbg-leaf"
PORT_RANGE = "56000-56079"
INTERFACE_PORT_RANGE = "55000-55079"
LANES = {
    "prod-dscp-global-single",
    "prerouting-port-interface-single",
    "port-global-hierarchy",
    "prod-dscp-global-hierarchy",
    "prerouting-dscp-global-hierarchy",
}
HIERARCHY_LANES = {
    "port-global-hierarchy",
    "prod-dscp-global-hierarchy",
    "prerouting-dscp-global-hierarchy",
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
        raise flow.CHRQoSPacketFlowError("hierarchy debug requires production prepare target")
    if str(target.get("interface") or "") != WAN:
        raise flow.CHRQoSPacketFlowError("hierarchy debug requires rendered ether2 WAN target")
    if not target.get("packet_mark") or not target.get("comment"):
        raise flow.CHRQoSPacketFlowError("hierarchy debug requires production EF classifier facts")
    return target


def _owned_queue_names(target: Mapping[str, Any]) -> set[str]:
    names = set(single._remove_queue_names(target))
    names.update({LAB_PARENT, LAB_CHILD, LAB_LEAF})
    return {name for name in names if name}


def _remove_commands(target: Mapping[str, Any]) -> list[str]:
    commands = [
        f"/queue/tree/remove [find where name={flat._quote(name)}]"
        for name in sorted(_owned_queue_names(target))
    ]
    commands.append(
        f"/ip/firewall/mangle/remove [find where comment={flat._quote(LAB_MARK_COMMENT)}]"
    )
    return commands


def _execute(admin: base.LoopbackCHRAdmin, commands: list[str]) -> Mapping[str, Any]:
    return flat._execute(admin, "\n".join(commands) + "\n")


def _remove_production_classifier(commands: list[str], target: Mapping[str, Any]) -> None:
    commands.append(
        f"/ip/firewall/mangle/remove [find where comment={flat._quote(str(target['comment']))}]"
    )


def _add_prerouting_marker(commands: list[str], *, dscp: int | None = None, port_range: str | None = None) -> None:
    terms = [
        "chain=prerouting",
        f"in-interface={flat._quote(INGRESS)}",
        "protocol=udp",
    ]
    if dscp is not None:
        terms.append(f"dscp={dscp}")
    if port_range is not None:
        terms.append(f"src-port={port_range}")
    terms.extend(
        (
            "packet-mark=no-mark",
            "action=mark-packet",
            f"new-packet-mark={flat._quote(LAB_MARK)}",
            "passthrough=no",
            f"comment={flat._quote(LAB_MARK_COMMENT)}",
            "disabled=no",
        )
    )
    commands.append("/ip/firewall/mangle/add " + " ".join(terms))


def _add_single_leaf(commands: list[str], *, parent: str, mark: str) -> None:
    commands.append(
        f"/queue/tree/add name={flat._quote(LAB_LEAF)} parent={flat._quote(parent)} "
        f"packet-mark={flat._quote(mark)} queue=default-small max-limit=100M disabled=no"
    )


def _add_global_hierarchy(commands: list[str], *, mark: str) -> None:
    commands.extend(
        (
            f"/queue/tree/add name={flat._quote(LAB_PARENT)} parent=global queue=default-small max-limit=100M disabled=no",
            (
                f"/queue/tree/add name={flat._quote(LAB_CHILD)} parent={flat._quote(LAB_PARENT)} "
                f"packet-mark={flat._quote(mark)} queue=default-small priority=1 "
                "limit-at=10M max-limit=100M disabled=no"
            ),
        )
    )


def install(*, admin_url: str, prepare: Mapping[str, Any], lane: str) -> dict[str, Any]:
    if lane not in LANES:
        raise flow.CHRQoSPacketFlowError(f"unsupported hierarchy debug lane: {lane}")
    admin = _admin(admin_url)
    target = _target(prepare)
    interface_names = {str(row.get("name") or "") for row in _rows(admin, "interface")}
    if not {INGRESS, WAN}.issubset(interface_names):
        raise flow.CHRQoSPacketFlowError("hierarchy debug requires ether2 WAN and ether3 CORE")

    commands = _remove_commands(target)
    production_classifier_retained = True
    classifier_kind = "production_forward_dscp46"
    mark = str(target["packet_mark"])

    if lane == "prod-dscp-global-single":
        _add_single_leaf(commands, parent="global", mark=mark)
    elif lane == "prerouting-port-interface-single":
        _add_prerouting_marker(commands, port_range=INTERFACE_PORT_RANGE)
        classifier_kind = "lab_prerouting_source_port"
        mark = LAB_MARK
        _add_single_leaf(commands, parent=WAN, mark=mark)
    elif lane == "port-global-hierarchy":
        _add_prerouting_marker(commands, port_range=PORT_RANGE)
        classifier_kind = "lab_prerouting_source_port"
        mark = LAB_MARK
        _add_global_hierarchy(commands, mark=mark)
    elif lane == "prod-dscp-global-hierarchy":
        _add_global_hierarchy(commands, mark=mark)
    else:
        _remove_production_classifier(commands, target)
        production_classifier_retained = False
        _add_prerouting_marker(commands, dscp=46)
        classifier_kind = "lab_prerouting_dscp46"
        mark = LAB_MARK
        _add_global_hierarchy(commands, mark=mark)

    execute = _execute(admin, commands)
    trees = _rows(admin, "queue/tree")
    if lane in HIERARCHY_LANES:
        parent = _one(trees, key="name", value=LAB_PARENT, label=f"{lane} parent")
        child = _one(trees, key="name", value=LAB_CHILD, label=f"{lane} child")
        if str(parent.get("parent") or "") != "global":
            raise flow.CHRQoSPacketFlowError(f"{lane} parent is not attached to global")
        if str(child.get("parent") or "") != LAB_PARENT:
            raise flow.CHRQoSPacketFlowError(f"{lane} child parent mismatch")
        if str(child.get("packet-mark") or "") != mark:
            raise flow.CHRQoSPacketFlowError(f"{lane} child packet mark mismatch")
        if base._is_true(parent.get("invalid")) or base._is_true(child.get("invalid")):
            raise flow.CHRQoSPacketFlowError(f"{lane} hierarchy is invalid")
    else:
        leaf = _one(trees, key="name", value=LAB_LEAF, label=f"{lane} leaf")
        expected_parent = "global" if lane == "prod-dscp-global-single" else WAN
        if str(leaf.get("parent") or "") != expected_parent:
            raise flow.CHRQoSPacketFlowError(f"{lane} single leaf parent mismatch")
        if str(leaf.get("packet-mark") or "") != mark:
            raise flow.CHRQoSPacketFlowError(f"{lane} single leaf packet mark mismatch")
        if base._is_true(leaf.get("invalid")):
            raise flow.CHRQoSPacketFlowError(f"{lane} single leaf is invalid")

    return {
        "ok": True,
        "lane": lane,
        "runtime_valid": True,
        "classifier_kind": classifier_kind,
        "packet_mark": mark,
        "production_classifier_retained": production_classifier_retained,
        "hierarchy": lane in HIERARCHY_LANES,
        "production_renderer_modified": False,
        "production_packet_flow_acceptance": False,
        "production_writer_available": False,
        "transport_exposed_to_product": False,
        "write_authorized": False,
        "physical_router_targeted": False,
        "execute": dict(execute),
    }


def counters(*, admin_url: str, prepare: Mapping[str, Any], lane: str) -> dict[str, Any]:
    admin = _admin(admin_url)
    target = _target(prepare)
    stats = _stats(admin)
    mangles = _rows(admin, "ip/firewall/mangle")
    result: dict[str, Any] = {
        "ok": True,
        "lane": lane,
        "counter_source": "queue_tree_print_stats",
    }

    if lane in HIERARCHY_LANES:
        parent = _one(stats, key="name", value=LAB_PARENT, label=f"{lane} parent stats")
        child = _one(stats, key="name", value=LAB_CHILD, label=f"{lane} child stats")
        result["parent_packets"] = _pc(parent, "hierarchy_parent")
        result["child_packets"] = _pc(child, "hierarchy_child")
    else:
        leaf = _one(stats, key="name", value=LAB_LEAF, label=f"{lane} leaf stats")
        result["leaf_packets"] = _pc(leaf, "single_leaf")

    if lane in {"prod-dscp-global-single", "prod-dscp-global-hierarchy"}:
        classifier = _one(mangles, key="comment", value=str(target["comment"]), label="production EF classifier")
    else:
        classifier = _one(mangles, key="comment", value=LAB_MARK_COMMENT, label="lab classifier")
    result["classifier_packets"] = _pc(classifier, "hierarchy_classifier")
    return result


def evaluate_single(*, lane: str, before: Mapping[str, Any], after: Mapping[str, Any], flow_payload: Mapping[str, Any]) -> dict[str, Any]:
    expected_dscp = 46 if lane == "prod-dscp-global-single" else 0
    if not flow._flow_ok(flow_payload, expected_dscp=expected_dscp):
        raise flow.CHRQoSPacketFlowError(f"{lane} flow was not reliable")
    classifier_delta = int(after["classifier_packets"]) - int(before["classifier_packets"])
    leaf_delta = int(after["leaf_packets"]) - int(before["leaf_packets"])
    if classifier_delta <= 0:
        raise flow.CHRQoSPacketFlowError(f"{lane} classifier counter did not increase")
    if leaf_delta <= 0:
        raise flow.CHRQoSPacketFlowError(f"{lane} leaf counter did not increase")
    return {
        "ok": True,
        "acceptance": "PASS",
        "lane": lane,
        "scope": "disposable_chr_single_leaf_attachment_debug",
        "classifier_packet_delta": classifier_delta,
        "leaf_packet_delta": leaf_delta,
        "successful_flows": int(flow_payload["successful_flows"]),
        "success_ratio": float(flow_payload["success_ratio"]),
        "production_packet_flow_acceptance": False,
        "production_renderer_modified": False,
        "production_writer_available": False,
        "physical_router_targeted": False,
    }


def evaluate_hierarchy(
    *,
    lane: str,
    before: Mapping[str, Any],
    after_default: Mapping[str, Any],
    after_special: Mapping[str, Any],
    default_flow: Mapping[str, Any],
    special_flow: Mapping[str, Any],
) -> dict[str, Any]:
    if lane not in HIERARCHY_LANES:
        raise flow.CHRQoSPacketFlowError("hierarchy evaluator requires hierarchy lane")
    if not flow._flow_ok(default_flow, expected_dscp=0):
        raise flow.CHRQoSPacketFlowError(f"{lane} default flow was not reliable")
    special_dscp = 0 if lane == "port-global-hierarchy" else 46
    if not flow._flow_ok(special_flow, expected_dscp=special_dscp):
        raise flow.CHRQoSPacketFlowError(f"{lane} special flow was not reliable")

    default_parent = int(after_default["parent_packets"]) - int(before["parent_packets"])
    default_child = int(after_default["child_packets"]) - int(before["child_packets"])
    default_classifier = int(after_default["classifier_packets"]) - int(before["classifier_packets"])
    special_parent = int(after_special["parent_packets"]) - int(after_default["parent_packets"])
    special_child = int(after_special["child_packets"]) - int(after_default["child_packets"])
    special_classifier = int(after_special["classifier_packets"]) - int(after_default["classifier_packets"])

    if default_parent <= 0:
        raise flow.CHRQoSPacketFlowError(f"{lane} parent did not own unmarked default traffic")
    if default_child != 0 or default_classifier != 0:
        raise flow.CHRQoSPacketFlowError(f"{lane} default traffic leaked into special classification")
    if special_classifier <= 0:
        raise flow.CHRQoSPacketFlowError(f"{lane} special classifier did not increase")
    if special_child <= 0:
        raise flow.CHRQoSPacketFlowError(f"{lane} special traffic did not traverse priority child")
    if special_parent <= 0:
        raise flow.CHRQoSPacketFlowError(f"{lane} parent aggregate did not observe special child traffic")

    return {
        "ok": True,
        "acceptance": "PASS",
        "lane": lane,
        "scope": "disposable_chr_parent_default_priority_child_debug",
        "default": {
            "parent_packet_delta": default_parent,
            "child_packet_delta": default_child,
            "classifier_packet_delta": default_classifier,
        },
        "special": {
            "parent_packet_delta": special_parent,
            "child_packet_delta": special_child,
            "classifier_packet_delta": special_classifier,
            "dscp": special_dscp,
        },
        "default_owned_by_parent": True,
        "special_owned_by_child": True,
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
    commands = _remove_commands(target)
    result = _execute(admin, commands)
    remaining = [row for row in _rows(admin, "queue/tree") if str(row.get("name") or "") in _owned_queue_names(target)]
    if remaining:
        raise flow.CHRQoSPacketFlowError("hierarchy debug cleanup left owned queue objects")
    return {
        "ok": True,
        "cleanup_complete": True,
        "production_packet_flow_acceptance": False,
        "execute": dict(result),
    }


def main() -> int:
    parser = argparse.ArgumentParser(description="Disposable CHR QoS hierarchy and attachment debug paths")
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
    p = sub.add_parser("evaluate-single")
    p.add_argument("--lane", choices=sorted(LANES - HIERARCHY_LANES), required=True)
    p.add_argument("--before", required=True)
    p.add_argument("--after", required=True)
    p.add_argument("--flow", required=True)
    p.add_argument("--output", required=True)
    p = sub.add_parser("evaluate-hierarchy")
    p.add_argument("--lane", choices=sorted(HIERARCHY_LANES), required=True)
    for flag in ("before", "after-default", "after-special", "default-flow", "special-flow"):
        p.add_argument(f"--{flag}", required=True)
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
    elif args.command == "evaluate-single":
        result = evaluate_single(lane=args.lane, before=_read(args.before), after=_read(args.after), flow_payload=_read(args.flow))
    elif args.command == "evaluate-hierarchy":
        result = evaluate_hierarchy(
            lane=args.lane,
            before=_read(args.before),
            after_default=_read(args.after_default),
            after_special=_read(args.after_special),
            default_flow=_read(args.default_flow),
            special_flow=_read(args.special_flow),
        )
    else:
        result = cleanup(admin_url=args.admin_url, prepare=_read(args.prepare))
    _write(args.output, result)
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
