from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any, Mapping

import diagnose_qos_flat_global as flat
import verify_qos_packet_flow as flow
import verify_render_dry_run as base


SINGLE_DEFAULT_LEAF = "routercfg-qos-single-default"
SINGLE_EF_LEAF = "routercfg-qos-single-ef"
SUPPORTED_MODES = {"default", "ef"}
SUPPORTED_QUEUES = {"default-small", "routercfg-qos-fq"}


def _read(path: str | Path) -> Any:
    return json.loads(Path(path).read_text(encoding="utf-8"))


def _write(path: str | Path, payload: Mapping[str, Any]) -> None:
    output = Path(path)
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def _remove_queue_names(target: Mapping[str, Any]) -> tuple[str, ...]:
    names = {
        str(target.get("priority_queue") or ""),
        str(target.get("default_queue") or ""),
        str(target.get("parent_queue") or ""),
        flat.DEFAULT_LEAF,
        flat.EF_LEAF,
        SINGLE_DEFAULT_LEAF,
        SINGLE_EF_LEAF,
        "routercfg-qos-diag-interface",
        "routercfg-qos-diag-global",
        "routercfg-qos-diag-global-parent",
        "routercfg-qos-diag-global-default",
        "routercfg-qos-diag-global-ef",
    }
    return tuple(sorted(name for name in names if name))


def _assert_queue_type(admin: base.LoopbackCHRAdmin, queue: str) -> None:
    if queue == "default-small":
        return
    qtypes = [
        row
        for row in flat._rows(admin, "queue/type")
        if str(row.get("name") or "") == queue
    ]
    if len(qtypes) != 1 or str(qtypes[0].get("kind") or "").lower() != "fq-codel":
        raise flow.CHRQoSPacketFlowError(
            "single-leaf FQ-CoDel queue type is not available from production prepare"
        )


def install(
    *,
    admin_url: str,
    prepare_payload: Mapping[str, Any],
    mode: str,
    queue: str,
) -> dict[str, Any]:
    if mode not in SUPPORTED_MODES:
        raise flow.CHRQoSPacketFlowError(f"unsupported single-leaf mode: {mode}")
    if queue not in SUPPORTED_QUEUES:
        raise flow.CHRQoSPacketFlowError(f"unsupported single-leaf queue: {queue}")

    admin = base.LoopbackCHRAdmin(admin_url)
    admin.assert_disposable_chr()
    target = prepare_payload.get("target")
    if not isinstance(target, Mapping):
        raise flow.CHRQoSPacketFlowError("single-leaf diagnostic requires production prepare target")

    interface = str(target.get("interface") or "")
    ef_mark = str(target.get("packet_mark") or "")
    ef_comment = str(target.get("comment") or "")
    if interface != "ether2" or not ef_mark or not ef_comment:
        raise flow.CHRQoSPacketFlowError(
            "single-leaf diagnostic requires rendered ether2 EF facts"
        )
    _assert_queue_type(admin, queue)

    commands = [
        f"/queue/tree/remove [find where name={flat._quote(name)}]"
        for name in _remove_queue_names(target)
    ]
    commands.append(
        f"/ip/firewall/mangle/remove [find where comment={flat._quote(flat.DEFAULT_COMMENT)}]"
    )

    if mode == "default":
        mark = flat.DEFAULT_MARK
        comment = flat.DEFAULT_COMMENT
        leaf = SINGLE_DEFAULT_LEAF
        commands.extend(
            (
                (
                    f"/ip/firewall/mangle/add chain=forward out-interface={flat._quote(interface)} "
                    f"packet-mark=no-mark action=mark-packet new-packet-mark={flat._quote(mark)} "
                    f"passthrough=no comment={flat._quote(comment)} disabled=no"
                ),
                (
                    f"/queue/tree/add name={flat._quote(leaf)} parent=global "
                    f"packet-mark={flat._quote(mark)} queue={flat._quote(queue)} "
                    "max-limit=100M disabled=no"
                ),
            )
        )
    else:
        mark = ef_mark
        comment = ef_comment
        leaf = SINGLE_EF_LEAF
        commands.append(
            (
                f"/queue/tree/add name={flat._quote(leaf)} parent=global "
                f"packet-mark={flat._quote(mark)} queue={flat._quote(queue)} "
                "max-limit=100M disabled=no"
            )
        )

    execute = flat._execute(admin, "\n".join(commands) + "\n")

    trees = flat._rows(admin, "queue/tree")
    selected = flat._one(trees, key="name", value=leaf, label=f"single {mode} leaf")
    sibling = SINGLE_EF_LEAF if mode == "default" else SINGLE_DEFAULT_LEAF
    if any(str(row.get("name") or "") == sibling for row in trees):
        raise flow.CHRQoSPacketFlowError("single-leaf diagnostic unexpectedly retained sibling leaf")
    if str(selected.get("parent") or "") != "global":
        raise flow.CHRQoSPacketFlowError("single-leaf parent is not global")
    if str(selected.get("packet-mark") or "") != mark:
        raise flow.CHRQoSPacketFlowError("single-leaf packet mark mismatch")
    if str(selected.get("queue") or "") != queue:
        raise flow.CHRQoSPacketFlowError("single-leaf queue type mismatch")
    if base._is_true(selected.get("invalid")) or base._is_true(selected.get("disabled")):
        raise flow.CHRQoSPacketFlowError("single-leaf queue is invalid or disabled")

    mangles = flat._rows(admin, "ip/firewall/mangle")
    selected_rule = flat._one(
        mangles,
        key="comment",
        value=comment,
        label=f"single {mode} mangle",
    )
    if str(selected_rule.get("new-packet-mark") or "") != mark:
        raise flow.CHRQoSPacketFlowError("single-leaf mangle mark mismatch")
    if mode == "ef" and str(selected_rule.get("dscp") or "") != "46":
        raise flow.CHRQoSPacketFlowError("production EF mangle did not retain DSCP 46")
    if mode == "ef":
        lab_default_rules = [
            row
            for row in mangles
            if str(row.get("comment") or "") == flat.DEFAULT_COMMENT
        ]
        if lab_default_rules:
            raise flow.CHRQoSPacketFlowError("EF-only mode unexpectedly created default lab mangle")

    return {
        "ok": True,
        "runtime_valid": True,
        "scope": "single_packet_mark_single_global_queue_tree_leaf",
        "mode": mode,
        "queue": queue,
        "interface": interface,
        "leaf": leaf,
        "packet_mark": mark,
        "mangle_comment": comment,
        "sibling_leaf_present": False,
        "priority_configured": False,
        "limit_at_configured": False,
        "production_mark_source_retained": mode == "ef",
        "production_renderer_modified": False,
        "production_packet_flow_acceptance": False,
        "production_writer_available": False,
        "transport_exposed_to_product": False,
        "write_authorized": False,
        "physical_router_targeted": False,
        "execute": dict(execute),
    }


def counters(*, admin_url: str, install_payload: Mapping[str, Any]) -> dict[str, Any]:
    admin = base.LoopbackCHRAdmin(admin_url)
    admin.assert_disposable_chr()
    stats = flat._stats_rows(admin)
    leaf = flat._one(
        stats,
        key="name",
        value=str(install_payload["leaf"]),
        label="single-leaf stats",
    )
    mangles = flat._rows(admin, "ip/firewall/mangle")
    rule = flat._one(
        mangles,
        key="comment",
        value=str(install_payload["mangle_comment"]),
        label="single-leaf mangle stats",
    )
    return {
        "ok": True,
        "counter_source": "queue_tree_print_stats",
        "mode": str(install_payload["mode"]),
        "queue": str(install_payload["queue"]),
        "leaf_packets": flow._int_counter(leaf, "packets", "single_leaf"),
        "mangle_packets": flow._int_counter(rule, "packets", "single_leaf_mangle"),
    }


def evaluate(
    *,
    mode: str,
    before: Mapping[str, Any],
    after: Mapping[str, Any],
    flow_payload: Mapping[str, Any],
) -> dict[str, Any]:
    if mode not in SUPPORTED_MODES:
        raise flow.CHRQoSPacketFlowError(f"unsupported single-leaf mode: {mode}")
    expected_dscp = 0 if mode == "default" else 46
    if not flow._flow_ok(flow_payload, expected_dscp=expected_dscp):
        raise flow.CHRQoSPacketFlowError(
            f"single-leaf {mode} flow did not traverse disposable CHR reliably"
        )
    if before.get("mode") != mode or after.get("mode") != mode:
        raise flow.CHRQoSPacketFlowError("single-leaf mode changed during measurement")
    if before.get("queue") != after.get("queue"):
        raise flow.CHRQoSPacketFlowError("single-leaf queue type changed during measurement")

    mangle_delta = int(after["mangle_packets"]) - int(before["mangle_packets"])
    leaf_delta = int(after["leaf_packets"]) - int(before["leaf_packets"])
    if mangle_delta <= 0:
        raise flow.CHRQoSPacketFlowError(
            f"single-leaf {mode} packet mark counter did not increase"
        )
    if leaf_delta <= 0:
        raise flow.CHRQoSPacketFlowError(
            f"single-leaf {mode} Queue Tree leaf counter did not increase"
        )

    return {
        "ok": True,
        "acceptance": "PASS",
        "scope": "diagnostic_single_mark_to_single_global_leaf_traversal",
        "mode": mode,
        "queue": str(before["queue"]),
        "expected_dscp": expected_dscp,
        "mangle_packet_delta": mangle_delta,
        "leaf_packet_delta": leaf_delta,
        "requested_flows": int(flow_payload["requested_flows"]),
        "successful_flows": int(flow_payload["successful_flows"]),
        "success_ratio": float(flow_payload["success_ratio"]),
        "diagnostic_packet_flow_acceptance": True,
        "production_packet_flow_acceptance": False,
        "aggregate_shaping_claimed": False,
        "latency_performance_claimed": False,
        "bandwidth_guarantee_claimed": False,
        "production_renderer_modified": False,
        "production_writer_available": False,
        "physical_router_targeted": False,
    }


def cleanup(*, admin_url: str) -> dict[str, Any]:
    admin = base.LoopbackCHRAdmin(admin_url)
    admin.assert_disposable_chr()
    commands = (
        f"/queue/tree/remove [find where name={flat._quote(SINGLE_DEFAULT_LEAF)}]",
        f"/queue/tree/remove [find where name={flat._quote(SINGLE_EF_LEAF)}]",
        f"/ip/firewall/mangle/remove [find where comment={flat._quote(flat.DEFAULT_COMMENT)}]",
    )
    execute = flat._execute(admin, "\n".join(commands) + "\n")
    remaining_tree = [
        row
        for row in flat._rows(admin, "queue/tree")
        if str(row.get("name") or "") in {SINGLE_DEFAULT_LEAF, SINGLE_EF_LEAF}
    ]
    remaining_default_rule = [
        row
        for row in flat._rows(admin, "ip/firewall/mangle")
        if str(row.get("comment") or "") == flat.DEFAULT_COMMENT
    ]
    if remaining_tree or remaining_default_rule:
        raise flow.CHRQoSPacketFlowError("single-leaf diagnostic cleanup left owned objects")
    return {
        "ok": True,
        "cleanup_complete": True,
        "production_ef_mangle_retained": True,
        "execute": dict(execute),
    }


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Probe one packet mark against exactly one global Queue Tree leaf"
    )
    sub = parser.add_subparsers(dest="command", required=True)

    p = sub.add_parser("install")
    p.add_argument("--admin-url", required=True)
    p.add_argument("--prepare", required=True)
    p.add_argument("--mode", choices=sorted(SUPPORTED_MODES), required=True)
    p.add_argument("--queue", choices=sorted(SUPPORTED_QUEUES), required=True)
    p.add_argument("--output", required=True)

    p = sub.add_parser("counters")
    p.add_argument("--admin-url", required=True)
    p.add_argument("--install", required=True)
    p.add_argument("--output", required=True)

    p = sub.add_parser("evaluate")
    p.add_argument("--mode", choices=sorted(SUPPORTED_MODES), required=True)
    p.add_argument("--before", required=True)
    p.add_argument("--after", required=True)
    p.add_argument("--flow", required=True)
    p.add_argument("--output", required=True)

    p = sub.add_parser("cleanup")
    p.add_argument("--admin-url", required=True)
    p.add_argument("--output", required=True)

    args = parser.parse_args()
    if args.command == "install":
        result = install(
            admin_url=args.admin_url,
            prepare_payload=_read(args.prepare),
            mode=args.mode,
            queue=args.queue,
        )
    elif args.command == "counters":
        result = counters(
            admin_url=args.admin_url,
            install_payload=_read(args.install),
        )
    elif args.command == "evaluate":
        result = evaluate(
            mode=args.mode,
            before=_read(args.before),
            after=_read(args.after),
            flow_payload=_read(args.flow),
        )
    else:
        result = cleanup(admin_url=args.admin_url)

    _write(args.output, result)
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
