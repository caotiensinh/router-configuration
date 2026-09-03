from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any, Mapping

import verify_qos_parent_default_runtime as legacy
import verify_mutation_rollback as mutation
import verify_render_dry_run as base
import verify_render_dry_run_chunked as chunked

from router_configuration.routeros_qos_renderer import render_routeros_qos


class CHRQoSRuntimeV2Error(RuntimeError):
    pass


def _rollback_script(plan: Mapping[str, Any]) -> str:
    target = plan["targets"][0]
    return "\n".join((
        f'/queue/tree/remove [find where name="{target["priority_queue"]}"]',
        f'/queue/tree/remove [find where name="{target["default_queue"]}"]',
        f'/queue/tree/remove [find where name="{target["parent_queue"]}"]',
        f'/ip/firewall/mangle/remove [find where comment="{target["comment"]}"]',
        f'/queue/type/remove [find where name="{plan["queue_type"]["name"]}"]',
    )) + "\n"


def _one(rows: list[Mapping[str, Any]], *, label: str, key: str, value: str) -> Mapping[str, Any]:
    matches = [row for row in rows if str(row.get(key) or "") == value]
    if len(matches) != 1:
        raise CHRQoSRuntimeV2Error(f"expected exactly one {label}, observed {len(matches)}")
    return matches[0]


def verify(*, admin_url: str) -> dict[str, Any]:
    admin = base.LoopbackCHRAdmin(admin_url)
    platform = admin.assert_disposable_chr()
    interfaces = {str(row.get("name") or "") for row in legacy._records(admin, "interface")}
    if not {"ether1", "ether2"}.issubset(interfaces):
        raise CHRQoSRuntimeV2Error("QoS runtime requires disposable CHR ether1 management and ether2 test WAN")

    plan = render_routeros_qos(ir=legacy._runtime_ir()).as_dict()
    target = plan["targets"][0]
    if not target.get("default_queue"):
        raise CHRQoSRuntimeV2Error("production renderer did not expose the default leaf queue")
    if plan.get("default_traffic_marked") is not False:
        raise CHRQoSRuntimeV2Error("production renderer unexpectedly marks default traffic")
    if len(plan.get("commands", [])) != 4:
        raise CHRQoSRuntimeV2Error("single-target QoS renderer must retain four high-level commands")
    if any(plan.get(field) is not expected for field, expected in (
        ("secrets_resolved", False), ("transport_present", False),
        ("apply_available", False), ("write_authorized", False),
    )):
        raise CHRQoSRuntimeV2Error("production renderer violated the generation-only boundary")

    baseline_sha = base._canonical_digest(legacy._snapshot(admin))
    for name in legacy.TEMP_FILES:
        base._delete_file_if_present(admin, name)

    mutated_sha = rollback_sha = None
    apply_result: Mapping[str, Any] | None = None
    rollback_result: Mapping[str, Any] | None = None
    try:
        chunked._create_text_file_chunk_verified(admin, legacy.APPLY_FILE, legacy._script_from_plan(plan))
        apply_result = mutation._execute_import(admin, file_name=legacy.APPLY_FILE, expect_success=True)

        mangle = _one(legacy._records(admin, "ip/firewall/mangle"), label="EF mangle", key="comment", value=str(target["comment"]))
        trees = legacy._records(admin, "queue/tree")
        parent = _one(trees, label="parent queue", key="name", value=str(target["parent_queue"]))
        default = _one(trees, label="default leaf", key="name", value=str(target["default_queue"]))
        priority = _one(trees, label="EF leaf", key="name", value=str(target["priority_queue"]))
        qtype = _one(legacy._records(admin, "queue/type"), label="FQ-CoDel type", key="name", value=str(plan["queue_type"]["name"]))

        managed = (mangle, parent, default, priority)
        invalid = sum(1 for row in managed if base._is_true(row.get("invalid")))
        disabled = sum(1 for row in managed if base._is_true(row.get("disabled")))
        if invalid or disabled:
            raise CHRQoSRuntimeV2Error(f"QoS runtime invalid={invalid} disabled={disabled}")
        if str(qtype.get("kind") or "").lower() != "fq-codel":
            raise CHRQoSRuntimeV2Error("managed queue type is not fq-codel")
        if str(mangle.get("out-interface") or "") != "ether2" or str(mangle.get("dscp") or "") != "46":
            raise CHRQoSRuntimeV2Error("EF mangle did not retain egress interface and DSCP 46")
        if str(parent.get("parent") or "") != "ether2":
            raise CHRQoSRuntimeV2Error("parent queue did not retain ether2")
        if str(default.get("parent") or "") != str(target["parent_queue"]) or str(default.get("packet-mark") or "") != "no-mark":
            raise CHRQoSRuntimeV2Error("default leaf did not retain parent/no-mark classification")
        if str(priority.get("parent") or "") != str(target["parent_queue"]) or str(priority.get("packet-mark") or "") != str(target["packet_mark"]):
            raise CHRQoSRuntimeV2Error("EF leaf did not retain parent/packet-mark binding")
        if str(priority.get("priority") or "") != "1":
            raise CHRQoSRuntimeV2Error("EF leaf did not retain priority 1")
        if str(default.get("priority") or "") != "8":
            raise CHRQoSRuntimeV2Error("default leaf did not retain priority 8")

        managed_mangle = [row for row in legacy._records(admin, "ip/firewall/mangle") if str(row.get("comment") or "").startswith("routercfg:managed:qos:")]
        if len(managed_mangle) != 1:
            raise CHRQoSRuntimeV2Error("QoS runtime must retain exactly one managed mangle rule per target")

        mutated_sha = base._canonical_digest(legacy._snapshot(admin))
        if mutated_sha == baseline_sha:
            raise CHRQoSRuntimeV2Error("QoS apply did not change configuration digest")

        chunked._create_text_file_chunk_verified(admin, legacy.ROLLBACK_FILE, _rollback_script(plan))
        rollback_result = mutation._execute_import(admin, file_name=legacy.ROLLBACK_FILE, expect_success=True)
        rollback_sha = base._canonical_digest(legacy._snapshot(admin))
        if rollback_sha != baseline_sha:
            raise CHRQoSRuntimeV2Error("QoS rollback did not restore exact baseline digest")
    finally:
        for name in legacy.TEMP_FILES:
            base._delete_file_if_present(admin, name)

    return {
        "ok": True,
        "acceptance": "PASS",
        "scope": "production_renderer_default_leaf_runtime_validity_and_exact_owned_rollback",
        "strategy": str(plan["strategy"]),
        "platform": {"version": str(platform.get("version") or ""), "architecture": str(platform.get("architecture-name") or ""), "board_name": str(platform.get("board-name") or "")},
        "renderer": {"production_renderer_used": True, "schema_version": str(plan["schema_version"]), "source_ir_sha256": str(plan["source_ir_sha256"]), "render_sha256": str(plan["render_sha256"]), "command_count": len(plan["commands"]), "default_traffic_marked": False},
        "runtime": {"managed_mangle_count": 1, "managed_queue_tree_count": 3, "managed_queue_type_count": 1, "invalid_managed_objects": 0, "disabled_managed_objects": 0, "default_mangle_count": 0, "default_leaf_packet_mark": "no-mark", "latency_dscp": 46, "latency_priority": 1, "default_priority": 8, "reserve_percent": 10},
        "apply": dict(apply_result or {}), "rollback": dict(rollback_result or {}),
        "configuration_baseline_sha256": baseline_sha, "configuration_mutated_sha256": mutated_sha, "configuration_rollback_sha256": rollback_sha,
        "rollback_digest_restored": rollback_sha == baseline_sha,
        "packet_flow_acceptance": False, "latency_performance_claimed": False,
        "production_writer_available": False, "transport_exposed_to_product": False, "write_authorized": False, "physical_router_targeted": False,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description="Validate default-leaf production QoS renderer on disposable RouterOS CHR")
    parser.add_argument("--admin-url", required=True)
    parser.add_argument("--output", required=True)
    args = parser.parse_args()
    result = verify(admin_url=args.admin_url)
    output = Path(args.output); output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
