from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any, Mapping

import verify_mutation_rollback as mutation
import verify_qos_packet_flow as legacy
import verify_render_dry_run as base
import verify_render_dry_run_chunked as chunked


SCRIPT_FILE = "routercfg-qos-global-hierarchy-diag.rsc"
PARENT = "routercfg-qos-diag-global-parent"
DEFAULT = "routercfg-qos-diag-global-default"
EF = "routercfg-qos-diag-global-ef"
DEFAULT_MARK = "routercfg-qos-diag-default"
DEFAULT_COMMENT = "routercfg:lab:qos-global:default"


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


def install(*, admin_url: str, prepare_payload: Mapping[str, Any]) -> dict[str, Any]:
    admin = base.LoopbackCHRAdmin(admin_url)
    admin.assert_disposable_chr()
    target = prepare_payload.get("target")
    if not isinstance(target, Mapping):
        raise legacy.CHRQoSPacketFlowError("global hierarchy diagnostic requires production prepare target")
    interface = str(target.get("interface") or "")
    ef_mark = str(target.get("packet_mark") or "")
    ef_comment = str(target.get("comment") or "")
    if interface != "ether2" or not ef_mark or not ef_comment:
        raise legacy.CHRQoSPacketFlowError("global hierarchy diagnostic requires rendered ether2 EF facts")

    remove_names = {
        str(target.get("priority_queue") or ""),
        str(target.get("default_queue") or ""),
        str(target.get("parent_queue") or ""),
        PARENT,
        DEFAULT,
        EF,
        "routercfg-qos-diag-interface",
        "routercfg-qos-diag-global",
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
            f"/queue/tree/add name={_quote(PARENT)} parent=global queue=default-small max-limit=100M disabled=no",
            (
                f"/queue/tree/add name={_quote(EF)} parent={_quote(PARENT)} packet-mark={_quote(ef_mark)} "
                "queue=default-small priority=1 limit-at=10M max-limit=100M disabled=no"
            ),
            (
                f"/queue/tree/add name={_quote(DEFAULT)} parent={_quote(PARENT)} packet-mark={_quote(DEFAULT_MARK)} "
                "queue=default-small priority=8 max-limit=100M disabled=no"
            ),
        )
    )
    execute = _execute(admin, "\n".join(commands) + "\n")

    mangle = _rows(admin, "ip/firewall/mangle")
    ef_rule = _one(mangle, key="comment", value=ef_comment, label="production EF mangle")
    default_rule = _one(mangle, key="comment", value=DEFAULT_COMMENT, label="diagnostic default mangle")
    trees = _rows(admin, "queue/tree")
    parent = _one(trees, key="name", value=PARENT, label="global parent")
    default = _one(trees, key="name", value=DEFAULT, label="global default child")
    ef = _one(trees, key="name", value=EF, label="global EF child")
    invalid = sum(1 for row in (parent, default, ef) if base._is_true(row.get("invalid")))
    disabled = sum(1 for row in (parent, default, ef) if base._is_true(row.get("disabled")))
    if invalid or disabled:
        raise legacy.CHRQoSPacketFlowError(f"global hierarchy invalid={invalid} disabled={disabled}")
    if str(ef_rule.get("new-packet-mark") or "") != ef_mark:
        raise legacy.CHRQoSPacketFlowError("production EF mark changed during global hierarchy diagnostic")
    if str(default_rule.get("new-packet-mark") or "") != DEFAULT_MARK:
        raise legacy.CHRQoSPacketFlowError("diagnostic default mark was not retained")
    if str(parent.get("parent") or "") != "global":
        raise legacy.CHRQoSPacketFlowError("diagnostic aggregate parent is not global")
    if str(default.get("packet-mark") or "") != DEFAULT_MARK:
        raise legacy.CHRQoSPacketFlowError("diagnostic default child mark mismatch")
    if str(ef.get("packet-mark") or "") != ef_mark:
        raise legacy.CHRQoSPacketFlowError("diagnostic EF child mark mismatch")
    return {
        "ok": True,
        "runtime_valid": True,
        "scope": "single_wan_global_parent_with_per_wan_default_and_ef_marks",
        "interface": interface,
        "parent": PARENT,
        "default_child": DEFAULT,
        "ef_child": EF,
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
    parent = _one(rows, key="name", value=str(install_payload["parent"]), label="global parent stats")
    default = _one(rows, key="name", value=str(install_payload["default_child"]), label="global default stats")
    ef = _one(rows, key="name", value=str(install_payload["ef_child"]), label="global EF stats")
    mangle = _rows(admin, "ip/firewall/mangle")
    default_rule = _one(mangle, key="comment", value=str(install_payload["default_comment"]), label="default mangle stats")
    ef_rule = _one(mangle, key="comment", value=str(install_payload["ef_comment"]), label="EF mangle stats")

    def pc(row: Mapping[str, Any], label: str) -> int:
        return legacy._int_counter(row, "packets", label)

    return {
        "ok": True,
        "counter_source": "queue_tree_print_stats",
        "parent_packets": pc(parent, "global_parent"),
        "default_child_packets": pc(default, "global_default"),
        "ef_child_packets": pc(ef, "global_ef"),
        "default_mangle_packets": pc(default_rule, "default_mangle"),
        "ef_mangle_packets": pc(ef_rule, "ef_mangle"),
    }


def evaluate(*, before: Mapping[str, Any], after_default: Mapping[str, Any], after_ef: Mapping[str, Any], default_flow: Mapping[str, Any], ef_flow: Mapping[str, Any]) -> dict[str, Any]:
    if not legacy._flow_ok(default_flow, expected_dscp=0):
        raise legacy.CHRQoSPacketFlowError("global hierarchy DSCP0 flow was not reliable")
    if not legacy._flow_ok(ef_flow, expected_dscp=46):
        raise legacy.CHRQoSPacketFlowError("global hierarchy DSCP46 flow was not reliable")

    def delta(after: Mapping[str, Any], first: Mapping[str, Any], key: str) -> int:
        return int(after[key]) - int(first[key])

    default_default_mark = delta(after_default, before, "default_mangle_packets")
    default_ef_mark = delta(after_default, before, "ef_mangle_packets")
    default_parent = delta(after_default, before, "parent_packets")
    default_leaf = delta(after_default, before, "default_child_packets")
    default_ef_leaf = delta(after_default, before, "ef_child_packets")

    ef_default_mark = delta(after_ef, after_default, "default_mangle_packets")
    ef_ef_mark = delta(after_ef, after_default, "ef_mangle_packets")
    ef_parent = delta(after_ef, after_default, "parent_packets")
    ef_default_leaf = delta(after_ef, after_default, "default_child_packets")
    ef_leaf = delta(after_ef, after_default, "ef_child_packets")

    if not (default_default_mark > 0 and default_ef_mark == 0 and default_parent > 0 and default_leaf > 0 and default_ef_leaf == 0):
        raise legacy.CHRQoSPacketFlowError("global hierarchy did not isolate DSCP0 into default mark/default leaf")
    if not (ef_default_mark == 0 and ef_ef_mark > 0 and ef_parent > 0 and ef_default_leaf == 0 and ef_leaf > 0):
        raise legacy.CHRQoSPacketFlowError("global hierarchy did not isolate DSCP46 into EF mark/EF leaf")

    return {
        "ok": True,
        "acceptance": "PASS",
        "scope": "single_wan_global_parent_default_and_ef_classification_and_queue_traversal",
        "classification": {
            "default_default_mark_delta": default_default_mark,
            "default_ef_mark_delta": default_ef_mark,
            "default_parent_delta": default_parent,
            "default_leaf_delta": default_leaf,
            "default_ef_leaf_delta": default_ef_leaf,
            "ef_default_mark_delta": ef_default_mark,
            "ef_ef_mark_delta": ef_ef_mark,
            "ef_parent_delta": ef_parent,
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
        f"/queue/tree/remove [find where name={_quote(EF)}]",
        f"/queue/tree/remove [find where name={_quote(DEFAULT)}]",
        f"/queue/tree/remove [find where name={_quote(PARENT)}]",
        f"/ip/firewall/mangle/remove [find where comment={_quote(DEFAULT_COMMENT)}]",
    )
    execute = _execute(admin, "\n".join(commands) + "\n")
    remaining_tree = [row for row in _rows(admin, "queue/tree") if str(row.get("name") or "") in {PARENT, DEFAULT, EF}]
    remaining_rule = [row for row in _rows(admin, "ip/firewall/mangle") if str(row.get("comment") or "") == DEFAULT_COMMENT]
    if remaining_tree or remaining_rule:
        raise legacy.CHRQoSPacketFlowError("global hierarchy diagnostic cleanup left owned objects")
    return {"ok": True, "cleanup_complete": True, "execute": dict(execute)}


def main() -> int:
    parser = argparse.ArgumentParser(description="Probe global Queue Tree hierarchy with per-WAN default and EF packet marks")
    sub = parser.add_subparsers(dest="command", required=True)
    p = sub.add_parser("install")
    p.add_argument("--admin-url", required=True)
    p.add_argument("--prepare", required=True)
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
        result = install(admin_url=args.admin_url, prepare_payload=_read(args.prepare))
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
