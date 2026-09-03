from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any, Mapping

import verify_qos_packet_flow as legacy
import verify_mutation_rollback as mutation
import verify_render_dry_run as base
import verify_render_dry_run_chunked as chunked


def _read(path: str | Path) -> Any:
    return json.loads(Path(path).read_text(encoding="utf-8"))


def _write(path: str | Path, payload: Mapping[str, Any]) -> None:
    output = Path(path); output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def _one(rows: list[Mapping[str, Any]], *, label: str, key: str, value: str) -> Mapping[str, Any]:
    matches = [row for row in rows if str(row.get(key) or "") == value]
    if len(matches) != 1:
        raise legacy.CHRQoSPacketFlowError(f"expected exactly one {label}, observed {len(matches)}")
    return matches[0]


def prepare(*, admin_url: str) -> dict[str, Any]:
    result = legacy.prepare(admin_url=admin_url)
    target = result.get("target")
    if not isinstance(target, Mapping) or not target.get("default_queue"):
        raise legacy.CHRQoSPacketFlowError("production renderer packet-flow target is missing default_queue")
    return result


def counters(*, admin_url: str, prepare_payload: Mapping[str, Any]) -> dict[str, Any]:
    admin = base.LoopbackCHRAdmin(admin_url)
    target = prepare_payload.get("target")
    qtype_payload = prepare_payload.get("queue_type")
    if not isinstance(target, Mapping) or not isinstance(qtype_payload, Mapping):
        raise legacy.CHRQoSPacketFlowError("counter snapshot requires prepare target and queue_type")

    mangle = _one(legacy._records(admin, "ip/firewall/mangle"), label="EF mangle", key="comment", value=str(target["comment"]))
    trees = legacy._records(admin, "queue/tree")
    parent = _one(trees, label="parent queue", key="name", value=str(target["parent_queue"]))
    default = _one(trees, label="default leaf", key="name", value=str(target["default_queue"]))
    priority = _one(trees, label="EF leaf", key="name", value=str(target["priority_queue"]))
    qtype = _one(legacy._records(admin, "queue/type"), label="FQ-CoDel type", key="name", value=str(qtype_payload["name"]))

    managed = (mangle, parent, default, priority)
    invalid = sum(1 for row in managed if base._is_true(row.get("invalid")))
    disabled = sum(1 for row in managed if base._is_true(row.get("disabled")))
    if invalid or disabled:
        raise legacy.CHRQoSPacketFlowError(f"managed QoS runtime invalid={invalid} disabled={disabled}")
    if str(qtype.get("kind") or "").lower() != "fq-codel":
        raise legacy.CHRQoSPacketFlowError("managed QoS queue type is not fq-codel")
    if str(default.get("packet-mark") or "") != "no-mark":
        raise legacy.CHRQoSPacketFlowError("default leaf does not use packet-mark=no-mark")
    if str(priority.get("packet-mark") or "") != str(target["packet_mark"]):
        raise legacy.CHRQoSPacketFlowError("EF leaf packet mark changed during packet-flow test")

    def values(row: Mapping[str, Any], label: str) -> dict[str, int]:
        return {"packets": legacy._int_counter(row, "packets", label), "bytes": legacy._int_counter(row, "bytes", label)}

    return {
        "ok": True,
        "mangle": values(mangle, "mangle"),
        "parent": values(parent, "parent"),
        "default_leaf": values(default, "default_leaf"),
        "priority_child": values(priority, "priority_child"),
        "runtime": {
            "invalid_managed_objects": 0, "disabled_managed_objects": 0,
            "default_leaf_packet_mark": "no-mark",
            "default_mangle_count": sum(1 for row in legacy._records(admin, "ip/firewall/mangle") if str(row.get("comment") or "").startswith("routercfg:managed:qos:") and "default" in str(row.get("comment") or "").lower()),
        },
    }


def evaluate(*, prepare_payload: Mapping[str, Any], before: Mapping[str, Any], after_default: Mapping[str, Any], after_ef: Mapping[str, Any], default_flow: Mapping[str, Any], ef_flow: Mapping[str, Any]) -> dict[str, Any]:
    if prepare_payload.get("ok") is not True:
        raise legacy.CHRQoSPacketFlowError("prepare evidence is not successful")
    if not legacy._flow_ok(default_flow, expected_dscp=0):
        raise legacy.CHRQoSPacketFlowError("default DSCP0 flow did not traverse disposable CHR reliably")
    if not legacy._flow_ok(ef_flow, expected_dscp=46):
        raise legacy.CHRQoSPacketFlowError("EF DSCP46 flow did not traverse disposable CHR reliably")

    def p(payload: Mapping[str, Any], queue: str) -> int:
        return int(payload[queue]["packets"])

    b_m, d_m, e_m = p(before, "mangle"), p(after_default, "mangle"), p(after_ef, "mangle")
    b_p, d_p, e_p = p(before, "parent"), p(after_default, "parent"), p(after_ef, "parent")
    b_d, d_d, e_d = p(before, "default_leaf"), p(after_default, "default_leaf"), p(after_ef, "default_leaf")
    b_e, d_e, e_e = p(before, "priority_child"), p(after_default, "priority_child"), p(after_ef, "priority_child")

    if d_m != b_m:
        raise legacy.CHRQoSPacketFlowError("DSCP0 traffic unexpectedly incremented EF mangle")
    if d_e != b_e:
        raise legacy.CHRQoSPacketFlowError("DSCP0 traffic unexpectedly incremented EF child")
    if d_d <= b_d:
        raise legacy.CHRQoSPacketFlowError("DSCP0 traffic did not traverse default no-mark leaf")
    if d_p <= b_p:
        raise legacy.CHRQoSPacketFlowError("DSCP0 traffic did not increment aggregate parent")
    if e_m <= d_m:
        raise legacy.CHRQoSPacketFlowError("DSCP46 traffic did not increment EF mangle")
    if e_e <= d_e:
        raise legacy.CHRQoSPacketFlowError("DSCP46 traffic did not traverse EF child")
    if e_p <= d_p:
        raise legacy.CHRQoSPacketFlowError("DSCP46 traffic did not increment aggregate parent")
    if e_d != d_d:
        raise legacy.CHRQoSPacketFlowError("DSCP46 traffic unexpectedly traversed default no-mark leaf")
    if int(after_ef["runtime"]["default_mangle_count"]) != 0:
        raise legacy.CHRQoSPacketFlowError("QoS runtime created an unexpected default mangle rule")

    return {
        "ok": True, "acceptance": "PASS", "scope": "qos_default_and_ef_leaf_classification_and_queue_traversal",
        "classification": {
            "default_dscp": 0, "latency_dscp": 46,
            "default_ef_mangle_delta": d_m - b_m, "default_parent_packet_delta": d_p - b_p,
            "default_leaf_packet_delta": d_d - b_d, "default_priority_child_delta": d_e - b_e,
            "ef_mangle_packet_delta": e_m - d_m, "ef_parent_packet_delta": e_p - d_p,
            "ef_default_leaf_delta": e_d - d_d, "ef_priority_child_delta": e_e - d_e,
            "default_mangle_count": 0,
        },
        "flows": {
            "default": {"requested": int(default_flow["requested_flows"]), "successful": int(default_flow["successful_flows"]), "success_ratio": float(default_flow["success_ratio"])},
            "ef": {"requested": int(ef_flow["requested_flows"]), "successful": int(ef_flow["successful_flows"]), "success_ratio": float(ef_flow["success_ratio"])},
        },
        "packet_flow_acceptance": True, "latency_performance_claimed": False, "bandwidth_guarantee_claimed": False,
        "production_writer_available": False, "transport_exposed_to_product": False, "write_authorized": False, "physical_router_targeted": False,
    }


def _rollback_script(plan: Mapping[str, Any]) -> str:
    target = plan["targets"][0]
    return "\n".join((
        f'/queue/tree/remove [find where name="{target["priority_queue"]}"]',
        f'/queue/tree/remove [find where name="{target["default_queue"]}"]',
        f'/queue/tree/remove [find where name="{target["parent_queue"]}"]',
        f'/ip/firewall/mangle/remove [find where comment="{target["comment"]}"]',
        f'/queue/type/remove [find where name="{plan["queue_type"]["name"]}"]',
        f'/ip/route/remove [find where comment="{legacy.LAB_ROUTE_COMMENT}"]',
        f'/ip/address/remove [find where comment="{legacy.LAB_CORE_COMMENT}"]',
        f'/ip/address/remove [find where comment="{legacy.LAB_WAN_COMMENT}"]',
    )) + "\n"


def finalize(*, admin_url: str, prepare_payload: Mapping[str, Any], evaluation: Mapping[str, Any]) -> dict[str, Any]:
    if evaluation.get("acceptance") != "PASS" or evaluation.get("packet_flow_acceptance") is not True:
        raise legacy.CHRQoSPacketFlowError("packet-flow evaluation must pass before rollback")
    admin = base.LoopbackCHRAdmin(admin_url)
    plan = legacy._render_plan()
    chunked._create_text_file_chunk_verified(admin, legacy.ROLLBACK_FILE, _rollback_script(plan))
    rollback_result = mutation._execute_import(admin, file_name=legacy.ROLLBACK_FILE, expect_success=True)
    rollback_sha = base._canonical_digest(legacy._configuration_snapshot(admin))
    baseline_sha = str(prepare_payload.get("configuration_baseline_sha256") or "")
    if rollback_sha != baseline_sha:
        raise legacy.CHRQoSPacketFlowError("QoS packet-flow rollback did not restore exact baseline digest")
    for name in (legacy.ROLLBACK_FILE, mutation.VERDICT_FILE):
        base._delete_file_if_present(admin, name)
    result = dict(evaluation)
    result.update({
        "platform": dict(prepare_payload.get("platform", {})), "renderer": dict(prepare_payload.get("renderer", {})), "target": dict(prepare_payload.get("target", {})),
        "rollback": dict(rollback_result), "configuration_baseline_sha256": baseline_sha,
        "configuration_mutated_sha256": str(prepare_payload.get("configuration_mutated_sha256") or ""),
        "configuration_rollback_sha256": rollback_sha, "rollback_digest_restored": True,
    })
    return result


def main() -> int:
    parser = argparse.ArgumentParser(description="QoS default/EF leaf packet-flow acceptance")
    sub = parser.add_subparsers(dest="command", required=True)
    a = sub.add_parser("prepare"); a.add_argument("--admin-url", required=True); a.add_argument("--output", required=True)
    a = sub.add_parser("counters"); a.add_argument("--admin-url", required=True); a.add_argument("--prepare", required=True); a.add_argument("--output", required=True)
    a = sub.add_parser("evaluate");
    for flag in ("prepare", "before", "after-default", "after-ef", "default-flow", "ef-flow"): a.add_argument(f"--{flag}", required=True)
    a.add_argument("--output", required=True)
    a = sub.add_parser("finalize"); a.add_argument("--admin-url", required=True); a.add_argument("--prepare", required=True); a.add_argument("--evaluation", required=True); a.add_argument("--output", required=True)
    args = parser.parse_args()
    if args.command == "prepare": result = prepare(admin_url=args.admin_url)
    elif args.command == "counters": result = counters(admin_url=args.admin_url, prepare_payload=_read(args.prepare))
    elif args.command == "evaluate": result = evaluate(prepare_payload=_read(args.prepare), before=_read(args.before), after_default=_read(args.after_default), after_ef=_read(args.after_ef), default_flow=_read(args.default_flow), ef_flow=_read(args.ef_flow))
    else: result = finalize(admin_url=args.admin_url, prepare_payload=_read(args.prepare), evaluation=_read(args.evaluation))
    _write(args.output, result); print(json.dumps(result, indent=2, sort_keys=True)); return 0


if __name__ == "__main__":
    raise SystemExit(main())
