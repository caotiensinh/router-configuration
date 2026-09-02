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


class CHRQoSBaselineError(RuntimeError):
    pass


APPLY_FILE = "routercfg-qos-baseline-apply.rsc"
ROLLBACK_FILE = "routercfg-qos-baseline-rollback.rsc"
TEMP_FILES = (APPLY_FILE, ROLLBACK_FILE, mutation.VERDICT_FILE)
WAN_NAME = "labwan"
WAN_INTERFACE = "ether2"
QUEUE_TYPE = "routercfg-fq-codel"
PARENT = "routercfg-qos-labwan"
VOICE = "routercfg-qos-labwan-voice"
DEFAULT = "routercfg-qos-labwan-default"
MANGLE_PREFIX = "routercfg:managed:qos:mark:labwan:"


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
        "mangle": _norm(admin, "ip/firewall/mangle", ("chain", "out-interface", "dscp", "packet-mark", "action", "new-packet-mark", "passthrough", "comment", "disabled")),
        "queue_tree": _norm(admin, "queue/tree", ("name", "parent", "packet-mark", "queue", "priority", "limit-at", "max-limit", "disabled")),
        "queue_type": _norm(admin, "queue/type", ("name", "kind")),
    }


def _live_state(admin: base.LoopbackCHRAdmin) -> dict[str, Any]:
    return {
        "firewall": {
            "filter": [dict(row) for row in _records(admin, "ip/firewall/filter")],
            "nat": [dict(row) for row in _records(admin, "ip/firewall/nat")],
        },
        "qos": {
            "simple_queues": [dict(row) for row in _records(admin, "queue/simple")],
            "queue_tree": [dict(row) for row in _records(admin, "queue/tree")],
            "queue_types": [dict(row) for row in _records(admin, "queue/type")],
        },
    }


def _ir() -> dict[str, Any]:
    payload = {
        "schema_version": "config-safe-subset-ir/1",
        "device_id": "chr-qos-baseline-lab",
        "operations": [
            {
                "operation_id": "qos.policy",
                "feature": "qos",
                "resource": "traffic_policy",
                "attributes": {
                    "enabled": True,
                    "policy": "latency_sensitive_first",
                    "classification": "existing_dscp_only",
                    "queue_kind": "fq-codel",
                    "egress_limits_mbps": {WAN_NAME: 100},
                    "classes": [
                        {"name": "voice", "priority": 1, "bandwidth_percent": 20, "default": False, "dscp": [46]},
                        {"name": "default", "priority": 8, "bandwidth_percent": 80, "default": True, "dscp": []},
                    ],
                },
                "risk": 30,
                "requires": ["qos"],
                "secret_references": [],
            },
            {
                "operation_id": "topology.wan.labwan",
                "feature": "topology",
                "resource": "wan_role",
                "attributes": {"name": WAN_NAME, "interface": WAN_INTERFACE, "capacity_mbps": 100, "addressing": "dhcp"},
                "risk": 20,
                "requires": ["interfaces"],
                "secret_references": [],
            },
        ],
        "vendor_commands_present": False,
        "write_transport_present": False,
    }
    payload["ir_sha256"] = hashlib.sha256(
        json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
    ).hexdigest()
    return payload


def _rollback_script() -> str:
    return "\n".join(
        (
            f'/queue/tree/remove [find where name="{DEFAULT}"]',
            f'/queue/tree/remove [find where name="{VOICE}"]',
            f'/queue/tree/remove [find where name="{PARENT}"]',
            f'/ip/firewall/mangle/remove [find where comment~"^{MANGLE_PREFIX}"]',
            f'/queue/type/remove [find where name="{QUEUE_TYPE}"]',
        )
    ) + "\n"


def _one(rows: list[Mapping[str, Any]], *, label: str, predicate) -> Mapping[str, Any]:
    matches = [row for row in rows if predicate(row)]
    if len(matches) != 1:
        raise CHRQoSBaselineError(f"expected exactly one {label}, observed {len(matches)}")
    return matches[0]


def verify(*, admin_url: str) -> dict[str, Any]:
    admin = base.LoopbackCHRAdmin(admin_url)
    platform = admin.assert_disposable_chr()
    interfaces = {str(row.get("name") or "") for row in _records(admin, "interface")}
    if not {"ether1", WAN_INTERFACE}.issubset(interfaces):
        raise CHRQoSBaselineError("QoS baseline requires ether1 management and ether2 test WAN")

    plan = render_routeros_qos(ir=_ir(), state=_live_state(admin)).as_dict()
    commands = plan.get("commands")
    if not isinstance(commands, list) or len(commands) != 5:
        raise CHRQoSBaselineError(f"QoS fixture requires exactly five generated commands, observed {len(commands) if isinstance(commands, list) else 'invalid'}")
    if plan.get("default_mangle_generated") is not False:
        raise CHRQoSBaselineError("QoS renderer unexpectedly generated default mangle")
    default_leaf = _one(
        commands,
        label="generated default leaf",
        predicate=lambda row: str(row.get("command_id") or "") == "qos.30.leaf.labwan.08.default",
    )
    if "packet-mark=no-mark" not in str(default_leaf.get("command") or ""):
        raise CHRQoSBaselineError("generated default leaf does not use packet-mark=no-mark")

    apply_script = "\n".join(str(item["command"]) for item in commands) + "\n"
    rollback_script = _rollback_script()
    for name in TEMP_FILES:
        base._delete_file_if_present(admin, name)
    baseline_sha = base._canonical_digest(_snapshot(admin))
    mutated_sha = None
    rollback_sha = None

    try:
        chunked._create_text_file_chunk_verified(admin, APPLY_FILE, apply_script)
        chunked._create_text_file_chunk_verified(admin, mutation.VERDICT_FILE, "PENDING")
        dry_run = base._execute_import_dry_run(
            admin,
            file_name=APPLY_FILE,
            verdict_name=mutation.VERDICT_FILE,
            expect_success=True,
        )
        if base._canonical_digest(_snapshot(admin)) != baseline_sha:
            raise CHRQoSBaselineError("QoS dry-run changed configuration")

        chunked._create_text_file_chunk_verified(admin, APPLY_FILE, apply_script)
        apply_result = mutation._execute_import(admin, file_name=APPLY_FILE, expect_success=True)

        mangle = [row for row in _records(admin, "ip/firewall/mangle") if str(row.get("comment") or "").startswith(MANGLE_PREFIX)]
        trees = [row for row in _records(admin, "queue/tree") if str(row.get("name") or "") in {PARENT, VOICE, DEFAULT}]
        qtype = _one(_records(admin, "queue/type"), label="managed FQ-CoDel type", predicate=lambda row: str(row.get("name") or "") == QUEUE_TYPE)
        if len(mangle) != 1 or len(trees) != 3:
            raise CHRQoSBaselineError(f"unexpected managed QoS object counts: mangle={len(mangle)} tree={len(trees)}")
        managed = [*mangle, *trees]
        invalid = sum(1 for row in managed if base._is_true(row.get("invalid")))
        disabled = sum(1 for row in managed if base._is_true(row.get("disabled")))
        if invalid or disabled:
            raise CHRQoSBaselineError(f"generated QoS runtime invalid/disabled: invalid={invalid} disabled={disabled}")
        default_runtime = _one(trees, label="runtime default leaf", predicate=lambda row: str(row.get("name") or "") == DEFAULT)
        if str(default_runtime.get("packet-mark") or "") != "no-mark":
            raise CHRQoSBaselineError("runtime default leaf lost packet-mark=no-mark")
        if str(qtype.get("kind") or "").lower() != "fq-codel":
            raise CHRQoSBaselineError("runtime managed queue type is not fq-codel")
        admin.request("GET", "system/resource")

        mutated_sha = base._canonical_digest(_snapshot(admin))
        if mutated_sha == baseline_sha:
            raise CHRQoSBaselineError("QoS apply did not change configuration digest")

        chunked._create_text_file_chunk_verified(admin, ROLLBACK_FILE, rollback_script)
        rollback_result = mutation._execute_import(admin, file_name=ROLLBACK_FILE, expect_success=True)
        rollback_sha = base._canonical_digest(_snapshot(admin))
        if rollback_sha != baseline_sha:
            raise CHRQoSBaselineError("QoS rollback did not restore exact baseline digest")
    finally:
        for name in TEMP_FILES:
            base._delete_file_if_present(admin, name)

    return {
        "ok": True,
        "acceptance": "PASS",
        "scope": "generated_qos_runtime_validity_management_survival_exact_rollback",
        "platform": {
            "version": str(platform.get("version") or ""),
            "architecture": str(platform.get("architecture-name") or ""),
            "board_name": str(platform.get("board-name") or ""),
        },
        "renderer": {
            "schema_version": str(plan.get("schema_version") or ""),
            "plan_sha256": str(plan.get("plan_sha256") or ""),
            "command_count": len(commands),
            "default_classification": str(plan.get("default_classification") or ""),
            "default_mangle_generated": False,
        },
        "dry_run": dry_run,
        "runtime": {
            "managed_mangle_count": 1,
            "managed_queue_tree_count": 3,
            "invalid_managed_objects": 0,
            "disabled_managed_objects": 0,
            "default_packet_mark": "no-mark",
            "queue_kind": "fq-codel",
            "management_rest_reachable_after_apply": True,
        },
        "apply": apply_result,
        "rollback": rollback_result,
        "configuration_baseline_sha256": baseline_sha,
        "configuration_mutated_sha256": mutated_sha,
        "configuration_rollback_sha256": rollback_sha,
        "rollback_digest_restored": rollback_sha == baseline_sha,
        "packet_flow_acceptance": False,
        "production_writer_available": False,
        "transport_exposed_to_product": False,
        "write_authorized": False,
        "physical_router_targeted": False,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description="Validate generated RouterOS QoS baseline on disposable CHR")
    parser.add_argument("--admin-url", default="http://127.0.0.1:9683")
    parser.add_argument("--output", required=True)
    args = parser.parse_args()
    output = Path(args.output)
    output.parent.mkdir(parents=True, exist_ok=True)
    try:
        result = verify(admin_url=args.admin_url)
        rc = 0
    except Exception as exc:
        result = {
            "ok": False,
            "acceptance": "FAIL",
            "error": str(exc),
            "packet_flow_acceptance": False,
            "production_writer_available": False,
            "transport_exposed_to_product": False,
            "write_authorized": False,
            "physical_router_targeted": False,
        }
        rc = 15
    output.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(json.dumps(result, indent=2, sort_keys=True))
    return rc


if __name__ == "__main__":
    raise SystemExit(main())
