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


class CHRQoSPacketFlowError(RuntimeError):
    pass


APPLY_FILE = "routercfg-qos-flow-apply.rsc"
ROLLBACK_FILE = "routercfg-qos-flow-rollback.rsc"
TEMP_FILES = (APPLY_FILE, ROLLBACK_FILE, mutation.VERDICT_FILE)
LAB_WAN_COMMENT = "routercfg:lab:qos-flow:wan"
LAB_CORE_COMMENT = "routercfg:lab:qos-flow:core"
LAB_ROUTE_COMMENT = "routercfg:lab:qos-flow:service"
SERVICE_IP = "203.0.113.100"


def _read_json(path: str | Path) -> Any:
    return json.loads(Path(path).read_text(encoding="utf-8"))


def _write_json(path: str | Path, payload: Mapping[str, Any]) -> None:
    output = Path(path)
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def _records(admin: base.LoopbackCHRAdmin, path: str) -> list[Mapping[str, Any]]:
    _, payload = admin.request("GET", path)
    return list(base._rows(payload))


def _norm(
    admin: base.LoopbackCHRAdmin,
    path: str,
    fields: tuple[str, ...],
) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for row in _records(admin, path):
        if base._is_true(row.get("dynamic")):
            continue
        rows.append({field: row[field] for field in fields if field in row})
    rows.sort(key=lambda item: json.dumps(item, sort_keys=True, ensure_ascii=False))
    return rows


def _configuration_snapshot(admin: base.LoopbackCHRAdmin) -> dict[str, Any]:
    return {
        "addresses": _norm(
            admin,
            "ip/address",
            ("address", "interface", "comment", "disabled"),
        ),
        "routes": _norm(
            admin,
            "ip/route",
            ("dst-address", "gateway", "routing-table", "comment", "disabled"),
        ),
        "mangle": _norm(
            admin,
            "ip/firewall/mangle",
            (
                "chain",
                "out-interface",
                "dscp",
                "packet-mark",
                "action",
                "new-packet-mark",
                "passthrough",
                "comment",
                "disabled",
            ),
        ),
        "queue_tree": _norm(
            admin,
            "queue/tree",
            (
                "name",
                "parent",
                "packet-mark",
                "queue",
                "priority",
                "limit-at",
                "max-limit",
                "disabled",
            ),
        ),
        "queue_type": _norm(admin, "queue/type", ("name", "kind")),
    }


def _runtime_ir() -> dict[str, Any]:
    payload: dict[str, Any] = {
        "schema_version": "config-safe-subset-ir/1",
        "device_id": "chr-qos-packet-flow",
        "operations": [
            {
                "operation_id": "qos.policy",
                "feature": "qos",
                "resource": "traffic_policy",
                "attributes": {"policy": "latency_sensitive_first"},
                "risk": 20,
                "requires": ["qos"],
                "secret_references": [],
            },
            {
                "operation_id": "topology.wan.wan-test",
                "feature": "topology",
                "resource": "wan_role",
                "attributes": {
                    "name": "wan-test",
                    "interface": "ether2",
                    "capacity_mbps": 100,
                    "addressing": "static",
                    "address": "192.0.2.2/30",
                },
                "risk": 20,
                "requires": ["interfaces"],
                "secret_references": [],
            },
        ],
        "vendor_commands_present": False,
        "write_transport_present": False,
    }
    canonical = json.dumps(
        payload,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
    ).encode("utf-8")
    payload["ir_sha256"] = hashlib.sha256(canonical).hexdigest()
    return payload


def _render_plan() -> dict[str, Any]:
    plan = render_routeros_qos(ir=_runtime_ir()).as_dict()
    if plan.get("strategy") != "parent_fq_codel_default_only_marked_priority_child":
        raise CHRQoSPacketFlowError("unexpected production QoS strategy")
    if plan.get("default_traffic_marked") is not False:
        raise CHRQoSPacketFlowError("production renderer unexpectedly marks default traffic")
    targets = plan.get("targets")
    commands = plan.get("commands")
    if not isinstance(targets, list) or len(targets) != 1:
        raise CHRQoSPacketFlowError("packet-flow fixture requires exactly one production QoS target")
    if not isinstance(commands, list) or len(commands) != 4:
        raise CHRQoSPacketFlowError("packet-flow fixture requires exactly four production QoS commands")
    return plan


def _production_script(plan: Mapping[str, Any]) -> str:
    commands = plan.get("commands")
    if not isinstance(commands, list):
        raise CHRQoSPacketFlowError("production QoS commands must be a list")
    rendered: list[str] = []
    for row in commands:
        if not isinstance(row, Mapping):
            raise CHRQoSPacketFlowError("production QoS command row must be an object")
        command = str(row.get("command") or "").strip()
        if not command:
            raise CHRQoSPacketFlowError("production QoS command must not be empty")
        rendered.append(command)
    return "\n".join(rendered) + "\n"


def _lab_network_script() -> str:
    return "\n".join(
        (
            f'/ip/address/add address="192.0.2.2/30" interface="ether2" comment="{LAB_WAN_COMMENT}"',
            f'/ip/address/add address="10.10.10.1/24" interface="ether3" comment="{LAB_CORE_COMMENT}"',
            f'/ip/route/add dst-address="{SERVICE_IP}/32" gateway="192.0.2.1" comment="{LAB_ROUTE_COMMENT}"',
        )
    ) + "\n"


def _rollback_script(plan: Mapping[str, Any]) -> str:
    targets = plan.get("targets")
    queue_type = plan.get("queue_type")
    if not isinstance(targets, list) or len(targets) != 1 or not isinstance(queue_type, Mapping):
        raise CHRQoSPacketFlowError("production QoS plan cannot build owned rollback")
    target = targets[0]
    if not isinstance(target, Mapping):
        raise CHRQoSPacketFlowError("production QoS target must be an object")
    child = str(target.get("priority_queue") or "")
    parent = str(target.get("parent_queue") or "")
    comment = str(target.get("comment") or "")
    qtype = str(queue_type.get("name") or "")
    if not all((child, parent, comment, qtype)):
        raise CHRQoSPacketFlowError("production QoS ownership identifiers are incomplete")
    return "\n".join(
        (
            f'/queue/tree/remove [find where name="{child}"]',
            f'/queue/tree/remove [find where name="{parent}"]',
            f'/ip/firewall/mangle/remove [find where comment="{comment}"]',
            f'/queue/type/remove [find where name="{qtype}"]',
            f'/ip/route/remove [find where comment="{LAB_ROUTE_COMMENT}"]',
            f'/ip/address/remove [find where comment="{LAB_CORE_COMMENT}"]',
            f'/ip/address/remove [find where comment="{LAB_WAN_COMMENT}"]',
        )
    ) + "\n"


def _owned_absent(admin: base.LoopbackCHRAdmin, plan: Mapping[str, Any]) -> None:
    target = plan["targets"][0]
    owned_comments = {str(target["comment"]), LAB_WAN_COMMENT, LAB_CORE_COMMENT, LAB_ROUTE_COMMENT}
    if any(str(row.get("comment") or "") in owned_comments for row in _records(admin, "ip/address")):
        raise CHRQoSPacketFlowError("baseline already contains an owned lab address")
    if any(str(row.get("comment") or "") in owned_comments for row in _records(admin, "ip/route")):
        raise CHRQoSPacketFlowError("baseline already contains an owned lab route")
    if any(str(row.get("comment") or "") == str(target["comment"]) for row in _records(admin, "ip/firewall/mangle")):
        raise CHRQoSPacketFlowError("baseline already contains the owned QoS mangle rule")
    if any(
        str(row.get("name") or "") in {str(target["parent_queue"]), str(target["priority_queue"])}
        for row in _records(admin, "queue/tree")
    ):
        raise CHRQoSPacketFlowError("baseline already contains an owned QoS queue tree")
    if any(str(row.get("name") or "") == str(plan["queue_type"]["name"]) for row in _records(admin, "queue/type")):
        raise CHRQoSPacketFlowError("baseline already contains the owned QoS queue type")


def prepare(*, admin_url: str) -> dict[str, Any]:
    admin = base.LoopbackCHRAdmin(admin_url)
    platform = admin.assert_disposable_chr()
    interfaces = {str(row.get("name") or "") for row in _records(admin, "interface")}
    if not {"ether1", "ether2", "ether3"}.issubset(interfaces):
        raise CHRQoSPacketFlowError("packet-flow lab requires ether1 management, ether2 WAN and ether3 CORE")

    plan = _render_plan()
    _owned_absent(admin, plan)
    baseline_sha = base._canonical_digest(_configuration_snapshot(admin))
    for name in TEMP_FILES:
        base._delete_file_if_present(admin, name)
    apply_script = _lab_network_script() + _production_script(plan)
    chunked._create_text_file_chunk_verified(admin, APPLY_FILE, apply_script)
    apply_result = mutation._execute_import(admin, file_name=APPLY_FILE, expect_success=True)
    mutated_sha = base._canonical_digest(_configuration_snapshot(admin))
    if mutated_sha == baseline_sha:
        raise CHRQoSPacketFlowError("packet-flow prepare did not change the configuration digest")
    for name in (APPLY_FILE, mutation.VERDICT_FILE):
        base._delete_file_if_present(admin, name)

    target = plan["targets"][0]
    return {
        "ok": True,
        "stage": "prepared",
        "platform": {
            "version": str(platform.get("version") or ""),
            "architecture": str(platform.get("architecture-name") or ""),
            "board_name": str(platform.get("board-name") or ""),
        },
        "renderer": {
            "production_renderer_used": True,
            "schema_version": str(plan["schema_version"]),
            "render_sha256": str(plan["render_sha256"]),
            "source_ir_sha256": str(plan["source_ir_sha256"]),
            "strategy": str(plan["strategy"]),
            "command_count": len(plan["commands"]),
            "default_traffic_marked": False,
        },
        "target": dict(target),
        "queue_type": dict(plan["queue_type"]),
        "apply": dict(apply_result),
        "configuration_baseline_sha256": baseline_sha,
        "configuration_mutated_sha256": mutated_sha,
        "packet_flow_acceptance": False,
        "latency_performance_claimed": False,
        "production_writer_available": False,
        "transport_exposed_to_product": False,
        "write_authorized": False,
        "physical_router_targeted": False,
    }


def _int_counter(row: Mapping[str, Any], field: str, label: str) -> int:
    if field not in row:
        raise CHRQoSPacketFlowError(f"{label} does not expose RouterOS runtime counter '{field}'")
    value = str(row.get(field) or "0").strip()
    try:
        return int(value)
    except ValueError as exc:
        raise CHRQoSPacketFlowError(f"{label}.{field} is not an integer: {value!r}") from exc


def counters(*, admin_url: str, prepare_payload: Mapping[str, Any]) -> dict[str, Any]:
    admin = base.LoopbackCHRAdmin(admin_url)
    target = prepare_payload.get("target")
    queue_type = prepare_payload.get("queue_type")
    if not isinstance(target, Mapping) or not isinstance(queue_type, Mapping):
        raise CHRQoSPacketFlowError("counter snapshot requires prepare target and queue_type")
    comment = str(target.get("comment") or "")
    parent_name = str(target.get("parent_queue") or "")
    child_name = str(target.get("priority_queue") or "")
    qtype_name = str(queue_type.get("name") or "")

    mangle_matches = [row for row in _records(admin, "ip/firewall/mangle") if str(row.get("comment") or "") == comment]
    tree_rows = _records(admin, "queue/tree")
    parent_matches = [row for row in tree_rows if str(row.get("name") or "") == parent_name]
    child_matches = [row for row in tree_rows if str(row.get("name") or "") == child_name]
    qtype_matches = [row for row in _records(admin, "queue/type") if str(row.get("name") or "") == qtype_name]
    if not all(len(rows) == 1 for rows in (mangle_matches, parent_matches, child_matches, qtype_matches)):
        raise CHRQoSPacketFlowError("managed QoS runtime object cardinality changed during packet-flow test")

    mangle = mangle_matches[0]
    parent = parent_matches[0]
    child = child_matches[0]
    qtype = qtype_matches[0]
    managed = (mangle, parent, child)
    invalid = sum(1 for row in managed if base._is_true(row.get("invalid")))
    disabled = sum(1 for row in managed if base._is_true(row.get("disabled")))
    if invalid or disabled:
        raise CHRQoSPacketFlowError(f"managed QoS runtime invalid={invalid} disabled={disabled}")
    if str(qtype.get("kind") or "").lower() != "fq-codel":
        raise CHRQoSPacketFlowError("managed QoS queue type is not fq-codel")

    return {
        "ok": True,
        "mangle": {
            "packets": _int_counter(mangle, "packets", "mangle"),
            "bytes": _int_counter(mangle, "bytes", "mangle"),
        },
        "parent": {
            "packets": _int_counter(parent, "packets", "parent"),
            "bytes": _int_counter(parent, "bytes", "parent"),
        },
        "priority_child": {
            "packets": _int_counter(child, "packets", "priority_child"),
            "bytes": _int_counter(child, "bytes", "priority_child"),
        },
        "runtime": {
            "invalid_managed_objects": 0,
            "disabled_managed_objects": 0,
            "parent_queue_kind": "fq-codel",
            "default_mangle_count": sum(
                1
                for row in _records(admin, "ip/firewall/mangle")
                if str(row.get("comment") or "").startswith("routercfg:managed:qos:")
                and "default" in str(row.get("comment") or "").lower()
            ),
        },
    }


def _flow_ok(payload: Mapping[str, Any], *, expected_dscp: int) -> bool:
    requested = int(payload.get("requested_flows") or 0)
    successful = int(payload.get("successful_flows") or 0)
    ratio = float(payload.get("success_ratio") or 0.0)
    tags = payload.get("tags")
    return (
        requested > 0
        and successful > 0
        and ratio >= 0.95
        and int(payload.get("dscp") or 0) == expected_dscp
        and isinstance(tags, Mapping)
        and int(tags.get("WAN") or 0) == successful
    )


def evaluate(
    *,
    prepare_payload: Mapping[str, Any],
    before: Mapping[str, Any],
    after_default: Mapping[str, Any],
    after_ef: Mapping[str, Any],
    default_flow: Mapping[str, Any],
    ef_flow: Mapping[str, Any],
) -> dict[str, Any]:
    if prepare_payload.get("ok") is not True:
        raise CHRQoSPacketFlowError("prepare evidence is not successful")
    if not _flow_ok(default_flow, expected_dscp=0):
        raise CHRQoSPacketFlowError("default DSCP0 flow did not traverse the disposable CHR reliably")
    if not _flow_ok(ef_flow, expected_dscp=46):
        raise CHRQoSPacketFlowError("EF DSCP46 flow did not traverse the disposable CHR reliably")

    b_m = int(before["mangle"]["packets"])
    d_m = int(after_default["mangle"]["packets"])
    e_m = int(after_ef["mangle"]["packets"])
    b_p = int(before["parent"]["packets"])
    d_p = int(after_default["parent"]["packets"])
    e_p = int(after_ef["parent"]["packets"])
    b_c = int(before["priority_child"]["packets"])
    d_c = int(after_default["priority_child"]["packets"])
    e_c = int(after_ef["priority_child"]["packets"])

    if d_m != b_m:
        raise CHRQoSPacketFlowError("DSCP0 traffic unexpectedly incremented the EF mangle counter")
    if d_c != b_c:
        raise CHRQoSPacketFlowError("DSCP0 traffic unexpectedly incremented the EF priority-child counter")
    if d_p <= b_p:
        raise CHRQoSPacketFlowError("DSCP0 traffic did not traverse the parent-default queue")
    if e_m <= d_m:
        raise CHRQoSPacketFlowError("DSCP46 traffic did not increment the EF mangle counter")
    if e_c <= d_c:
        raise CHRQoSPacketFlowError("DSCP46 traffic did not traverse the EF priority-child queue")
    if e_p <= d_p:
        raise CHRQoSPacketFlowError("DSCP46 traffic did not increment the aggregate parent queue")
    if int(after_ef["runtime"]["default_mangle_count"]) != 0:
        raise CHRQoSPacketFlowError("QoS runtime created an unexpected default traffic mangle rule")

    return {
        "ok": True,
        "acceptance": "PASS",
        "scope": "qos_classification_and_queue_traversal",
        "classification": {
            "default_dscp": 0,
            "latency_dscp": 46,
            "default_ef_mangle_delta": d_m - b_m,
            "default_parent_packet_delta": d_p - b_p,
            "default_priority_child_delta": d_c - b_c,
            "ef_mangle_packet_delta": e_m - d_m,
            "ef_parent_packet_delta": e_p - d_p,
            "ef_priority_child_delta": e_c - d_c,
            "default_mangle_count": 0,
        },
        "flows": {
            "default": {
                "requested": int(default_flow["requested_flows"]),
                "successful": int(default_flow["successful_flows"]),
                "success_ratio": float(default_flow["success_ratio"]),
            },
            "ef": {
                "requested": int(ef_flow["requested_flows"]),
                "successful": int(ef_flow["successful_flows"]),
                "success_ratio": float(ef_flow["success_ratio"]),
            },
        },
        "packet_flow_acceptance": True,
        "latency_performance_claimed": False,
        "bandwidth_guarantee_claimed": False,
        "production_writer_available": False,
        "transport_exposed_to_product": False,
        "write_authorized": False,
        "physical_router_targeted": False,
    }


def finalize(
    *,
    admin_url: str,
    prepare_payload: Mapping[str, Any],
    evaluation: Mapping[str, Any],
) -> dict[str, Any]:
    if evaluation.get("acceptance") != "PASS" or evaluation.get("packet_flow_acceptance") is not True:
        raise CHRQoSPacketFlowError("packet-flow evaluation must pass before rollback finalization")
    admin = base.LoopbackCHRAdmin(admin_url)
    plan = _render_plan()
    chunked._create_text_file_chunk_verified(admin, ROLLBACK_FILE, _rollback_script(plan))
    rollback_result = mutation._execute_import(admin, file_name=ROLLBACK_FILE, expect_success=True)
    rollback_sha = base._canonical_digest(_configuration_snapshot(admin))
    baseline_sha = str(prepare_payload.get("configuration_baseline_sha256") or "")
    if rollback_sha != baseline_sha:
        raise CHRQoSPacketFlowError("QoS packet-flow rollback did not restore exact baseline digest")
    for name in (ROLLBACK_FILE, mutation.VERDICT_FILE):
        base._delete_file_if_present(admin, name)

    result = dict(evaluation)
    result.update(
        {
            "platform": dict(prepare_payload.get("platform", {})),
            "renderer": dict(prepare_payload.get("renderer", {})),
            "target": dict(prepare_payload.get("target", {})),
            "rollback": dict(rollback_result),
            "configuration_baseline_sha256": baseline_sha,
            "configuration_mutated_sha256": str(prepare_payload.get("configuration_mutated_sha256") or ""),
            "configuration_rollback_sha256": rollback_sha,
            "rollback_digest_restored": True,
        }
    )
    return result


def main() -> int:
    parser = argparse.ArgumentParser(description="QoS packet-flow acceptance on disposable RouterOS CHR")
    sub = parser.add_subparsers(dest="command", required=True)

    p_prepare = sub.add_parser("prepare")
    p_prepare.add_argument("--admin-url", required=True)
    p_prepare.add_argument("--output", required=True)

    p_counters = sub.add_parser("counters")
    p_counters.add_argument("--admin-url", required=True)
    p_counters.add_argument("--prepare", required=True)
    p_counters.add_argument("--output", required=True)

    p_eval = sub.add_parser("evaluate")
    p_eval.add_argument("--prepare", required=True)
    p_eval.add_argument("--before", required=True)
    p_eval.add_argument("--after-default", required=True)
    p_eval.add_argument("--after-ef", required=True)
    p_eval.add_argument("--default-flow", required=True)
    p_eval.add_argument("--ef-flow", required=True)
    p_eval.add_argument("--output", required=True)

    p_final = sub.add_parser("finalize")
    p_final.add_argument("--admin-url", required=True)
    p_final.add_argument("--prepare", required=True)
    p_final.add_argument("--evaluation", required=True)
    p_final.add_argument("--output", required=True)

    args = parser.parse_args()
    if args.command == "prepare":
        result = prepare(admin_url=args.admin_url)
    elif args.command == "counters":
        result = counters(admin_url=args.admin_url, prepare_payload=_read_json(args.prepare))
    elif args.command == "evaluate":
        result = evaluate(
            prepare_payload=_read_json(args.prepare),
            before=_read_json(args.before),
            after_default=_read_json(args.after_default),
            after_ef=_read_json(args.after_ef),
            default_flow=_read_json(args.default_flow),
            ef_flow=_read_json(args.ef_flow),
        )
    elif args.command == "finalize":
        result = finalize(
            admin_url=args.admin_url,
            prepare_payload=_read_json(args.prepare),
            evaluation=_read_json(args.evaluation),
        )
    else:
        raise AssertionError(args.command)

    _write_json(args.output, result)
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
