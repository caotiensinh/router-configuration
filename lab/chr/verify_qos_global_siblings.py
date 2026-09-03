from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
from typing import Any, Mapping

import verify_mutation_rollback as mutation
import verify_render_dry_run as base
import verify_render_dry_run_chunked as chunked

from router_configuration.routeros_qos_renderer import render_routeros_qos


class CHRQoSGlobalSiblingError(RuntimeError):
    pass


APPLY_FILE = "routercfg-qos-global-apply.rsc"
ROLLBACK_FILE = "routercfg-qos-global-rollback.rsc"
LAB_WAN_COMMENT = "routercfg:lab:qos-global:wan"
LAB_CORE_COMMENT = "routercfg:lab:qos-global:core"
LAB_ROUTE_COMMENT = "routercfg:lab:qos-global:service"
SERVICE_IP = "203.0.113.100"


def _read(path: str | Path) -> Any:
    return json.loads(Path(path).read_text(encoding="utf-8"))


def _write(path: str | Path, payload: Mapping[str, Any]) -> None:
    output = Path(path)
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def _records(admin: base.LoopbackCHRAdmin, path: str) -> list[Mapping[str, Any]]:
    _, payload = admin.request("GET", path)
    return list(base._rows(payload))


def _norm(admin: base.LoopbackCHRAdmin, path: str, fields: tuple[str, ...]) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for row in _records(admin, path):
        if base._is_true(row.get("dynamic")):
            continue
        rows.append({field: row[field] for field in fields if field in row})
    rows.sort(key=lambda item: json.dumps(item, sort_keys=True, ensure_ascii=False))
    return rows


def _snapshot(admin: base.LoopbackCHRAdmin) -> dict[str, Any]:
    return {
        "addresses": _norm(admin, "ip/address", ("address", "interface", "comment", "disabled")),
        "routes": _norm(admin, "ip/route", ("dst-address", "gateway", "comment", "disabled")),
        "mangle": _norm(admin, "ip/firewall/mangle", ("chain", "out-interface", "dscp", "packet-mark", "action", "new-packet-mark", "passthrough", "comment", "disabled")),
        "queue_tree": _norm(admin, "queue/tree", ("name", "parent", "packet-mark", "queue", "priority", "limit-at", "max-limit", "disabled")),
        "queue_type": _norm(admin, "queue/type", ("name", "kind")),
    }


def _runtime_ir() -> dict[str, Any]:
    payload: dict[str, Any] = {
        "schema_version": "config-safe-subset-ir/1",
        "device_id": "chr-qos-global-siblings",
        "operations": [
            {"operation_id": "qos.policy", "feature": "qos", "resource": "traffic_policy", "attributes": {"policy": "latency_sensitive_first"}, "risk": 20, "requires": ["qos"], "secret_references": []},
            {"operation_id": "topology.wan.wan-test", "feature": "topology", "resource": "wan_role", "attributes": {"name": "wan-test", "interface": "ether2", "capacity_mbps": 100, "addressing": "static", "address": "192.0.2.2/30"}, "risk": 20, "requires": ["interfaces"], "secret_references": []},
        ],
        "vendor_commands_present": False,
        "write_transport_present": False,
    }
    canonical = json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
    payload["ir_sha256"] = hashlib.sha256(canonical).hexdigest()
    return payload


def _plan() -> dict[str, Any]:
    plan = render_routeros_qos(ir=_runtime_ir()).as_dict()
    if plan.get("strategy") != "global_sibling_fq_codel_unmarked_default_marked_priority":
        raise CHRQoSGlobalSiblingError("unexpected production QoS strategy")
    if plan.get("default_traffic_marked") is not False:
        raise CHRQoSGlobalSiblingError("production renderer unexpectedly marks default traffic")
    if plan.get("policy_contract", {}).get("latency_performance_claimed") is not False:
        raise CHRQoSGlobalSiblingError("production renderer overclaims latency performance")
    targets = plan.get("targets")
    commands = plan.get("commands")
    if not isinstance(targets, list) or len(targets) != 1:
        raise CHRQoSGlobalSiblingError("acceptance fixture requires exactly one QoS target")
    if not isinstance(commands, list) or len(commands) != 4:
        raise CHRQoSGlobalSiblingError("acceptance fixture requires exactly four production QoS commands")
    return plan


def _script(plan: Mapping[str, Any]) -> str:
    rows = plan.get("commands")
    if not isinstance(rows, list):
        raise CHRQoSGlobalSiblingError("production commands missing")
    return "\n".join(str(row["command"]).strip() for row in rows if isinstance(row, Mapping)) + "\n"


def _lab_script() -> str:
    return "\n".join((
        f'/ip/address/add address="192.0.2.2/30" interface="ether2" comment="{LAB_WAN_COMMENT}"',
        f'/ip/address/add address="10.10.10.1/24" interface="ether3" comment="{LAB_CORE_COMMENT}"',
        f'/ip/route/add dst-address="{SERVICE_IP}/32" gateway="192.0.2.1" comment="{LAB_ROUTE_COMMENT}"',
    )) + "\n"


def _rollback(plan: Mapping[str, Any]) -> str:
    target = plan["targets"][0]
    return "\n".join((
        f'/queue/tree/remove [find where name="{target["priority_queue"]}"]',
        f'/queue/tree/remove [find where name="{target["default_queue"]}"]',
        f'/ip/firewall/mangle/remove [find where comment="{target["comment"]}"]',
        f'/queue/type/remove [find where name="{plan["queue_type"]["name"]}"]',
        f'/ip/route/remove [find where comment="{LAB_ROUTE_COMMENT}"]',
        f'/ip/address/remove [find where comment="{LAB_CORE_COMMENT}"]',
        f'/ip/address/remove [find where comment="{LAB_WAN_COMMENT}"]',
    )) + "\n"


def _one(rows: list[Mapping[str, Any]], key: str, value: str, label: str) -> Mapping[str, Any]:
    matches = [row for row in rows if str(row.get(key) or "") == value]
    if len(matches) != 1:
        raise CHRQoSGlobalSiblingError(f"expected one {label}, observed {len(matches)}")
    return matches[0]


def _counter(row: Mapping[str, Any], field: str, label: str) -> int:
    try:
        return int(str(row.get(field, "0")))
    except ValueError as exc:
        raise CHRQoSGlobalSiblingError(f"{label}.{field} is not an integer") from exc


def prepare(admin_url: str) -> dict[str, Any]:
    admin = base.LoopbackCHRAdmin(admin_url)
    platform = admin.assert_disposable_chr()
    interfaces = {str(row.get("name") or "") for row in _records(admin, "interface")}
    if not {"ether1", "ether2", "ether3"}.issubset(interfaces):
        raise CHRQoSGlobalSiblingError("lab requires ether1 management, ether2 WAN, ether3 CORE")
    plan = _plan()
    target = plan["targets"][0]
    owned_names = {str(target["default_queue"]), str(target["priority_queue"])}
    if any(str(row.get("name") or "") in owned_names for row in _records(admin, "queue/tree")):
        raise CHRQoSGlobalSiblingError("baseline contains owned QoS queue")
    baseline = base._canonical_digest(_snapshot(admin))
    for name in (APPLY_FILE, ROLLBACK_FILE, mutation.VERDICT_FILE):
        base._delete_file_if_present(admin, name)
    chunked._create_text_file_chunk_verified(admin, APPLY_FILE, _lab_script() + _script(plan))
    applied = mutation._execute_import(admin, file_name=APPLY_FILE, expect_success=True)
    mutated = base._canonical_digest(_snapshot(admin))
    if mutated == baseline:
        raise CHRQoSGlobalSiblingError("apply did not mutate configuration")
    for name in (APPLY_FILE, mutation.VERDICT_FILE):
        base._delete_file_if_present(admin, name)
    return {
        "ok": True,
        "platform": {"version": str(platform.get("version") or ""), "architecture": str(platform.get("architecture-name") or ""), "board_name": str(platform.get("board-name") or "")},
        "renderer": {"production_renderer_used": True, "strategy": plan["strategy"], "schema_version": plan["schema_version"], "render_sha256": plan["render_sha256"], "source_ir_sha256": plan["source_ir_sha256"], "command_count": len(plan["commands"]), "default_traffic_marked": False},
        "target": dict(target), "queue_type": dict(plan["queue_type"]), "apply": dict(applied),
        "configuration_baseline_sha256": baseline, "configuration_mutated_sha256": mutated,
        "packet_flow_acceptance": False, "aggregate_shaping_claimed": False, "bandwidth_guarantee_claimed": False, "latency_performance_claimed": False,
        "production_writer_available": False, "transport_exposed_to_product": False, "write_authorized": False, "physical_router_targeted": False,
    }


def counters(admin_url: str, prepared: Mapping[str, Any]) -> dict[str, Any]:
    admin = base.LoopbackCHRAdmin(admin_url)
    target = prepared["target"]
    _, stats_payload = admin.request("POST", "queue/tree/print", {"stats": ""})
    trees = list(base._rows(stats_payload))
    default = _one(trees, "name", str(target["default_queue"]), "default leaf")
    ef = _one(trees, "name", str(target["priority_queue"]), "EF leaf")
    mangle = _one(_records(admin, "ip/firewall/mangle"), "comment", str(target["comment"]), "EF mangle")
    qtype = _one(_records(admin, "queue/type"), "name", str(prepared["queue_type"]["name"]), "FQ-CoDel queue type")
    managed = (default, ef, mangle)
    invalid = sum(1 for row in managed if base._is_true(row.get("invalid")))
    disabled = sum(1 for row in managed if base._is_true(row.get("disabled")))
    if invalid or disabled:
        raise CHRQoSGlobalSiblingError(f"managed objects invalid={invalid} disabled={disabled}")
    if str(qtype.get("kind") or "").lower() != "fq-codel":
        raise CHRQoSGlobalSiblingError("queue type is not fq-codel")
    if str(default.get("parent") or "") != "ether2" or str(ef.get("parent") or "") != "ether2":
        raise CHRQoSGlobalSiblingError("global sibling leaves are not both parented to ether2")
    if str(default.get("packet-mark") or "") != "no-mark":
        raise CHRQoSGlobalSiblingError("default leaf is not packet-mark=no-mark")
    if str(ef.get("packet-mark") or "") != str(target["packet_mark"]):
        raise CHRQoSGlobalSiblingError("EF leaf mark does not match production renderer")
    if str(default.get("priority") or "") != "8" or str(ef.get("priority") or "") != "1":
        raise CHRQoSGlobalSiblingError("global sibling priorities changed")
    default_mangle_count = sum(1 for row in _records(admin, "ip/firewall/mangle") if str(row.get("comment") or "").startswith("routercfg:managed:qos:") and "default" in str(row.get("comment") or "").lower())
    return {
        "ok": True, "counter_source": "queue_tree_print_stats",
        "default_leaf": {"packets": _counter(default, "packets", "default"), "bytes": _counter(default, "bytes", "default")},
        "ef_leaf": {"packets": _counter(ef, "packets", "ef"), "bytes": _counter(ef, "bytes", "ef")},
        "mangle": {"packets": _counter(mangle, "packets", "mangle"), "bytes": _counter(mangle, "bytes", "mangle")},
        "runtime": {"invalid_managed_objects": 0, "disabled_managed_objects": 0, "default_mangle_count": default_mangle_count, "default_leaf_packet_mark": "no-mark", "queue_kind": "fq-codel"},
    }


def _flow_ok(flow: Mapping[str, Any], dscp: int) -> bool:
    return int(flow.get("dscp", -1)) == dscp and int(flow.get("requested_flows", 0)) > 0 and float(flow.get("success_ratio", 0.0)) >= 0.95


def evaluate(before: Mapping[str, Any], after_default: Mapping[str, Any], after_ef: Mapping[str, Any], default_flow: Mapping[str, Any], ef_flow: Mapping[str, Any]) -> dict[str, Any]:
    if not _flow_ok(default_flow, 0) or not _flow_ok(ef_flow, 46):
        raise CHRQoSGlobalSiblingError("DSCP0/46 end-to-end flow acceptance below 95%")
    def p(src: Mapping[str, Any], key: str) -> int:
        return int(src[key]["packets"])
    b_d, d_d, e_d = p(before, "default_leaf"), p(after_default, "default_leaf"), p(after_ef, "default_leaf")
    b_e, d_e, e_e = p(before, "ef_leaf"), p(after_default, "ef_leaf"), p(after_ef, "ef_leaf")
    b_m, d_m, e_m = p(before, "mangle"), p(after_default, "mangle"), p(after_ef, "mangle")
    if d_d <= b_d or d_e != b_e or d_m != b_m:
        raise CHRQoSGlobalSiblingError("DSCP0 did not exclusively traverse default no-mark leaf")
    if e_e <= d_e or e_m <= d_m:
        raise CHRQoSGlobalSiblingError("DSCP46 did not traverse production EF classifier and leaf")
    if e_d != d_d:
        raise CHRQoSGlobalSiblingError("DSCP46 unexpectedly traversed default no-mark leaf")
    if int(after_ef["runtime"]["default_mangle_count"]) != 0:
        raise CHRQoSGlobalSiblingError("unexpected default mangle rule exists")
    return {
        "ok": True, "acceptance": "PASS", "scope": "qos_global_sibling_default_and_ef_packet_flow", "packet_flow_acceptance": True,
        "classification": {"default_leaf_packet_delta": d_d - b_d, "default_ef_leaf_delta": d_e - b_e, "default_ef_mangle_delta": d_m - b_m, "ef_leaf_packet_delta": e_e - d_e, "ef_mangle_packet_delta": e_m - d_m, "ef_default_leaf_delta": e_d - d_d, "default_mangle_count": 0},
        "flows": {"default": {"requested": int(default_flow["requested_flows"]), "successful": int(default_flow["successful_flows"]), "success_ratio": float(default_flow["success_ratio"])}, "ef": {"requested": int(ef_flow["requested_flows"]), "successful": int(ef_flow["successful_flows"]), "success_ratio": float(ef_flow["success_ratio"])}},
        "aggregate_shaping_claimed": False, "bandwidth_guarantee_claimed": False, "latency_performance_claimed": False,
        "production_writer_available": False, "transport_exposed_to_product": False, "write_authorized": False, "physical_router_targeted": False,
    }


def finalize(admin_url: str, prepared: Mapping[str, Any], evaluation: Mapping[str, Any]) -> dict[str, Any]:
    if evaluation.get("packet_flow_acceptance") is not True:
        raise CHRQoSGlobalSiblingError("evaluation must pass before rollback")
    admin = base.LoopbackCHRAdmin(admin_url)
    plan = _plan()
    chunked._create_text_file_chunk_verified(admin, ROLLBACK_FILE, _rollback(plan))
    rollback = mutation._execute_import(admin, file_name=ROLLBACK_FILE, expect_success=True)
    rollback_sha = base._canonical_digest(_snapshot(admin))
    baseline_sha = str(prepared["configuration_baseline_sha256"])
    if rollback_sha != baseline_sha:
        raise CHRQoSGlobalSiblingError("rollback did not restore exact baseline digest")
    for name in (ROLLBACK_FILE, mutation.VERDICT_FILE):
        base._delete_file_if_present(admin, name)
    result = dict(evaluation)
    result.update({"platform": dict(prepared["platform"]), "renderer": dict(prepared["renderer"]), "target": dict(prepared["target"]), "rollback": dict(rollback), "configuration_baseline_sha256": baseline_sha, "configuration_mutated_sha256": str(prepared["configuration_mutated_sha256"]), "configuration_rollback_sha256": rollback_sha, "rollback_digest_restored": True})
    return result


def main() -> int:
    parser = argparse.ArgumentParser()
    sub = parser.add_subparsers(dest="command", required=True)
    p = sub.add_parser("prepare"); p.add_argument("--admin-url", required=True); p.add_argument("--output", required=True)
    p = sub.add_parser("counters"); p.add_argument("--admin-url", required=True); p.add_argument("--prepare", required=True); p.add_argument("--output", required=True)
    p = sub.add_parser("evaluate")
    for flag in ("before", "after-default", "after-ef", "default-flow", "ef-flow"): p.add_argument(f"--{flag}", required=True)
    p.add_argument("--output", required=True)
    p = sub.add_parser("finalize"); p.add_argument("--admin-url", required=True); p.add_argument("--prepare", required=True); p.add_argument("--evaluation", required=True); p.add_argument("--output", required=True)
    args = parser.parse_args()
    if args.command == "prepare": result = prepare(args.admin_url)
    elif args.command == "counters": result = counters(args.admin_url, _read(args.prepare))
    elif args.command == "evaluate": result = evaluate(_read(args.before), _read(args.after_default), _read(args.after_ef), _read(args.default_flow), _read(args.ef_flow))
    else: result = finalize(args.admin_url, _read(args.prepare), _read(args.evaluation))
    _write(args.output, result); print(json.dumps(result, indent=2, sort_keys=True)); return 0


if __name__ == "__main__":
    raise SystemExit(main())
