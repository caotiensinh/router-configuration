from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any, Mapping

import verify_mutation_rollback as mutation
import verify_qos_packet_flow as legacy
import verify_render_dry_run as base
import verify_render_dry_run_chunked as chunked


SCRIPT_FILE = "routercfg-qos-flat-global-diag.rsc"
DEFAULT_MARK = "routercfg-qos-flat-default"
DEFAULT_COMMENT = "routercfg:lab:qos-flat:default"
DEFAULT_LEAF = "routercfg-qos-flat-default"
EF_LEAF = "routercfg-qos-flat-ef"
SUPPORTED_QUEUES = {"default-small", "routercfg-qos-fq"}


def _read(path: str | Path) -> Any:
    return json.loads(Path(path).read_text(encoding="utf-8"))


def _write(path: str | Path, payload: Mapping[str, Any]) -> None:
    output = Path(path)
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def _rows(admin: base.LoopbackCHRAdmin, path: str) -> list[Mapping[str, Any]]:
    _, payload = admin.request("GET", path)
    return list(base._rows(payload))


def _stats_rows(admin: base.LoopbackCHRAdmin) -> list[Mapping[str, Any]]:
    _, payload = admin.request("POST", "queue/tree/print", {"stats": ""})
    return list(base._rows(payload))


def _quote(value: str) -> str:
    return '"' + value.replace("\\", "\\\\").replace('"', '\\"') + '"'


def _execute(admin: base.LoopbackCHRAdmin, script: str) -> Mapping[str, Any]:
    for name in (SCRIPT_FILE, mutation.VERDICT_FILE):
        base._delete_file_if_present(admin, name)
    try:
        chunked._create_text_file_chunk_verified(admin, SCRIPT_FILE, script)
        return mutation._execute_import(admin, file_name=SCRIPT_FILE, expect_success=True)
    finally:
        for name in (SCRIPT_FILE, mutation.VERDICT_FILE):
            base._delete_file_if_present(admin, name)


def _one(rows: list[Mapping[str, Any]], *, key: str, value: str, label: str) -> Mapping[str, Any]:
    matches = [row for row in rows if str(row.get(key) or "") == value]
    if len(matches) != 1:
        raise legacy.CHRQoSPacketFlowError(f"expected exactly one {label}, observed {len(matches)}")
    return matches[0]


def install(*, admin_url: str, prepare_payload: Mapping[str, Any], queue: str) -> dict[str, Any]:
    if queue not in SUPPORTED_QUEUES:
        raise legacy.CHRQoSPacketFlowError(f"unsupported flat-global queue: {queue}")
    admin = base.LoopbackCHRAdmin(admin_url)
    admin.assert_disposable_chr()
    target = prepare_payload.get("target")
    if not isinstance(target, Mapping):
        raise legacy.CHRQoSPacketFlowError("flat-global diagnostic requires production prepare target")
    interface = str(target.get("interface") or "")
    ef_mark = str(target.get("packet_mark") or "")
    ef_comment = str(target.get("comment") or "")
    if interface != "ether2" or not ef_mark or not ef_comment:
        raise legacy.CHRQoSPacketFlowError("flat-global diagnostic requires rendered ether2 EF facts")
    if queue == "routercfg-qos-fq":
        qtypes = [row for row in _rows(admin, "queue/type") if str(row.get("name") or "") == queue]
        if len(qtypes) != 1 or str(qtypes[0].get("kind") or "").lower() != "fq-codel":
            raise legacy.CHRQoSPacketFlowError("flat-global FQ-CoDel queue type is not available from production prepare")

    remove_names = {
        str(target.get("priority_queue") or ""),
        str(target.get("default_queue") or ""),
        str(target.get("parent_queue") or ""),
        "routercfg-qos-diag-interface",
        "routercfg-qos-diag-global",
        "routercfg-qos-diag-global-parent",
        "routercfg-qos-diag-global-default",
        "routercfg-qos-diag-global-ef",
        DEFAULT_LEAF,
        EF_LEAF,
    }
    commands = [f"/queue/tree/remove [find where name={_quote(name)}]" for name in sorted(remove_names) if name]
    commands.extend(
        (
            f"/ip/firewall/mangle/remove [find where comment={_quote(DEFAULT_COMMENT)}]",
            (
                f"/ip/firewall/mangle/add chain=forward out-interface={_quote(interface)} "
                f"packet-mark=no-mark action=mark-packet new-packet-mark={_quote(DEFAULT_MARK)} "
                f"passthrough=no comment={_quote(DEFAULT_COMMENT)} disabled=no"
            ),
            (
                f"/queue/tree/add name={_quote(EF_LEAF)} parent=global packet-mark={_quote(ef_mark)} "
                f"queue={_quote(queue)} priority=1 limit-at=10M max-limit=100M disabled=no"
            ),
            (
                f"/queue/tree/add name={_quote(DEFAULT_LEAF)} parent=global packet-mark={_quote(DEFAULT_MARK)} "
                f"queue={_quote(queue)} priority=8 max-limit=100M disabled=no"
            ),
        )
    )
    execute = _execute(admin, "\n".join(commands) + "\n")

    mangle = _rows(admin, "ip/firewall/mangle")
    ef_rule = _one(mangle, key="comment", value=ef_comment, label="production EF mangle")
    default_rule = _one(mangle, key="comment", value=DEFAULT_COMMENT, label="flat default mangle")
    trees = _rows(admin, "queue/tree")
    default = _one(trees, key="name", value=DEFAULT_LEAF, label="flat default leaf")
    ef = _one(trees, key="name", value=EF_LEAF, label="flat EF leaf")
    invalid = sum(1 for row in (default, ef) if base._is_true(row.get("invalid")))
    disabled = sum(1 for row in (default, ef) if base._is_true(row.get("disabled")))
    if invalid or disabled:
        raise legacy.CHRQoSPacketFlowError(f"flat-global leaves invalid={invalid} disabled={disabled}")
    if str(ef_rule.get("new-packet-mark") or "") != ef_mark:
        raise legacy.CHRQoSPacketFlowError("production EF mark changed during flat-global diagnostic")
    if str(default_rule.get("new-packet-mark") or "") != DEFAULT_MARK:
        raise legacy.CHRQoSPacketFlowError("flat-global default mark was not retained")
    for row, mark, label in ((ef, ef_mark, "EF"), (default, DEFAULT_MARK, "default")):
        if str(row.get("parent") or "") != "global":
            raise legacy.CHRQoSPacketFlowError(f"flat-global {label} leaf parent is not global")
        if str(row.get("packet-mark") or "") != mark:
            raise legacy.CHRQoSPacketFlowError(f"flat-global {label} leaf packet mark mismatch")
        if str(row.get("queue") or "") != queue:
            raise legacy.CHRQoSPacketFlowError(f"flat-global {label} leaf queue type mismatch")
    return {
        "ok": True,
        "runtime_valid": True,
        "scope": "single_wan_flat_global_default_and_ef_leaves",
        "interface": interface,
        "queue": queue,
        "default_leaf": DEFAULT_LEAF,
        "ef_leaf": EF_LEAF,
        "default_mark": DEFAULT_MARK,
        "ef_mark": ef_mark,
        "default_comment": DEFAULT_COMMENT,
        "ef_comment": ef_comment,
        "execute": dict(execute),
        "production_renderer_modified": False,
        "production_writer_available": False,
        "physical_router_targeted": False,
    }


def counters(*, admin_url: str, install_payload: Mapping[str, Any]) -> dict[str, Any]:
    admin = base.LoopbackCHRAdmin(admin_url)
    admin.assert_disposable_chr()
    rows = _stats_rows(admin)
    default = _one(rows, key="name", value=str(install_payload["default_leaf"]), label="flat default stats")
    ef = _one(rows, key="name", value=str(install_payload["ef_leaf"]), label="flat EF stats")
    mangle = _rows(admin, "ip/firewall/mangle")
    default_rule = _one(mangle, key="comment", value=str(install_payload["default_comment"]), label="flat default mangle stats")
    ef_rule = _one(mangle, key="comment", value=str(install_payload["ef_comment"]), label="flat EF mangle stats")

    def pc(row: Mapping[str, Any], label: str) -> int:
        return legacy._int_counter(row, "packets", label)

    return {
        "ok": True,
        "counter_source": "queue_tree_print_stats",
        "queue": str(install_payload["queue"]),
        "default_leaf_packets": pc(default, "flat_default"),
        "ef_leaf_packets": pc(ef, "flat_ef"),
        "default_mangle_packets": pc(default_rule, "flat_default_mangle"),
        "ef_mangle_packets": pc(ef_rule, "flat_ef_mangle"),
    }


def evaluate(*, before: Mapping[str, Any], after_default: Mapping[str, Any], after_ef: Mapping[str, Any], default_flow: Mapping[str, Any], ef_flow: Mapping[str, Any]) -> dict[str, Any]:
    if not legacy._flow_ok(default_flow, expected_dscp=0):
        raise legacy.CHRQoSPacketFlowError("flat-global DSCP0 flow was not reliable")
    if not legacy._flow_ok(ef_flow, expected_dscp=46):
        raise legacy.CHRQoSPacketFlowError("flat-global DSCP46 flow was not reliable")
    if before.get("queue") != after_default.get("queue") or before.get("queue") != after_ef.get("queue"):
        raise legacy.CHRQoSPacketFlowError("flat-global queue type changed during measurement")

    def delta(after: Mapping[str, Any], first: Mapping[str, Any], key: str) -> int:
        return int(after[key]) - int(first[key])

    default_default_mark = delta(after_default, before, "default_mangle_packets")
    default_ef_mark = delta(after_default, before, "ef_mangle_packets")
    default_leaf = delta(after_default, before, "default_leaf_packets")
    default_ef_leaf = delta(after_default, before, "ef_leaf_packets")
    ef_default_mark = delta(after_ef, after_default, "default_mangle_packets")
    ef_ef_mark = delta(after_ef, after_default, "ef_mangle_packets")
    ef_default_leaf = delta(after_ef, after_default, "default_leaf_packets")
    ef_leaf = delta(after_ef, after_default, "ef_leaf_packets")

    if not (default_default_mark > 0 and default_ef_mark == 0 and default_leaf > 0 and default_ef_leaf == 0):
        raise legacy.CHRQoSPacketFlowError("flat-global DSCP0 did not isolate into default mark/default leaf")
    if not (ef_default_mark == 0 and ef_ef_mark > 0 and ef_default_leaf == 0 and ef_leaf > 0):
        raise legacy.CHRQoSPacketFlowError("flat-global DSCP46 did not isolate into EF mark/EF leaf")

    return {
        "ok": True,
        "acceptance": "PASS",
        "scope": "single_wan_flat_global_default_and_ef_classification_and_queue_traversal",
        "queue": str(before["queue"]),
        "classification": {
            "default_default_mark_delta": default_default_mark,
            "default_ef_mark_delta": default_ef_mark,
            "default_leaf_delta": default_leaf,
            "default_ef_leaf_delta": default_ef_leaf,
            "ef_default_mark_delta": ef_default_mark,
            "ef_ef_mark_delta": ef_ef_mark,
            "ef_default_leaf_delta": ef_default_leaf,
            "ef_leaf_delta": ef_leaf,
        },
        "flows": {
            "default_success_ratio": float(default_flow["success_ratio"]),
            "ef_success_ratio": float(ef_flow["success_ratio"]),
        },
        "packet_flow_acceptance": True,
        "single_wan_only": True,
        "multi_wan_isolation_claimed": False,
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
        f"/queue/tree/remove [find where name={_quote(EF_LEAF)}]",
        f"/queue/tree/remove [find where name={_quote(DEFAULT_LEAF)}]",
        f"/ip/firewall/mangle/remove [find where comment={_quote(DEFAULT_COMMENT)}]",
    )
    execute = _execute(admin, "\n".join(commands) + "\n")
    remaining_tree = [row for row in _rows(admin, "queue/tree") if str(row.get("name") or "") in {DEFAULT_LEAF, EF_LEAF}]
    remaining_rule = [row for row in _rows(admin, "ip/firewall/mangle") if str(row.get("comment") or "") == DEFAULT_COMMENT]
    if remaining_tree or remaining_rule:
        raise legacy.CHRQoSPacketFlowError("flat-global diagnostic cleanup left owned objects")
    return {"ok": True, "cleanup_complete": True, "execute": dict(execute)}


def main() -> int:
    parser = argparse.ArgumentParser(description="Probe flat direct-global Queue Tree leaves with per-WAN default and EF packet marks")
    sub = parser.add_subparsers(dest="command", required=True)
    p = sub.add_parser("install")
    p.add_argument("--admin-url", required=True)
    p.add_argument("--prepare", required=True)
    p.add_argument("--queue", choices=sorted(SUPPORTED_QUEUES), required=True)
    p.add_argument("--output", required=True)
    p = sub.add_parser("counters")
    p.add_argument("--admin-url", required=True)
    p.add_argument("--install", required=True)
    p.add_argument("--output", required=True)
    p = sub.add_parser("evaluate")
    for flag in ("before", "after-default", "after-ef", "default-flow", "ef-flow"):
        p.add_argument(f"--{flag}", required=True)
    p.add_argument("--output", required=True)
    p = sub.add_parser("cleanup")
    p.add_argument("--admin-url", required=True)
    p.add_argument("--output", required=True)
    args = parser.parse_args()

    if args.command == "install":
        result = install(admin_url=args.admin_url, prepare_payload=_read(args.prepare), queue=args.queue)
    elif args.command == "counters":
        result = counters(admin_url=args.admin_url, install_payload=_read(args.install))
    elif args.command == "evaluate":
        result = evaluate(
            before=_read(args.before),
            after_default=_read(args.after_default),
            after_ef=_read(args.after_ef),
            default_flow=_read(args.default_flow),
            ef_flow=_read(args.ef_flow),
        )
    else:
        result = cleanup(admin_url=args.admin_url)
    _write(args.output, result)
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
