from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any, Mapping

import verify_mutation_rollback as mutation
import verify_render_dry_run as base
import verify_render_dry_run_chunked as chunked
from router_configuration.routeros_qos_renderer import render_routeros_qos
from router_configuration.safe_subset_ir import IntentOperation, IntentRisk, SafeSubsetIR


class CHRQoSBaselineError(RuntimeError):
    pass


APPLY_FILE = "routercfg-qos-apply.rsc"
ROLLBACK_FILE = "routercfg-qos-rollback.rsc"
VERDICT_FILE = "routercfg-qos-verdict.txt"
TEMP_FILES = (APPLY_FILE, ROLLBACK_FILE, VERDICT_FILE, mutation.VERDICT_FILE)
QUEUE_TYPE = "routercfg-fq-codel"
WAN_NAME = "lab-wan"
WAN_INTERFACE = "ether2"
PARENT_NAME = "routercfg-qos-lab-wan"
VOICE_NAME = "routercfg-qos-lab-wan-voice"
DEFAULT_NAME = "routercfg-qos-lab-wan-default"
COMMENT_PREFIX = "routercfg:managed:qos:"


def _records(admin: base.LoopbackCHRAdmin, path: str) -> list[Mapping[str, Any]]:
    _, payload = admin.request("GET", path)
    return list(base._rows(payload))


def _live_renderer_state(admin: base.LoopbackCHRAdmin) -> dict[str, Any]:
    """Use live CHR conflict surfaces rather than invented empty state."""

    return {
        "firewall": {"filter": [dict(row) for row in _records(admin, "ip/firewall/filter")]},
        "qos": {
            "simple_queues": [dict(row) for row in _records(admin, "queue/simple")],
            "queue_tree": [dict(row) for row in _records(admin, "queue/tree")],
            "queue_types": [dict(row) for row in _records(admin, "queue/type")],
        },
    }


def _build_ir() -> dict[str, Any]:
    return SafeSubsetIR(
        device_id="chr-qos-baseline-lab",
        operations=(
            IntentOperation(
                operation_id=f"topology.wan.{WAN_NAME}",
                feature="topology",
                resource="wan_role",
                attributes={
                    "name": WAN_NAME,
                    "interface": WAN_INTERFACE,
                    "capacity_mbps": 1000,
                },
                risk=IntentRisk.MEDIUM,
                requires=("interfaces",),
            ),
            IntentOperation(
                operation_id="qos.policy",
                feature="qos",
                resource="traffic_policy",
                attributes={
                    "policy": "latency_sensitive_first",
                    "classification": "existing_dscp_only",
                    "queue_kind": "fq-codel",
                    "egress_limits_mbps": {WAN_NAME: 100},
                    "classes": [
                        {
                            "name": "voice",
                            "priority": 1,
                            "bandwidth_percent": 20,
                            "dscp": [46],
                            "default": False,
                        },
                        {
                            "name": "default",
                            "priority": 8,
                            "bandwidth_percent": 80,
                            "dscp": [],
                            "default": True,
                        },
                    ],
                },
                risk=IntentRisk.MEDIUM,
                requires=("qos",),
            ),
        ),
    ).as_dict()


def _normalized_rows(
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
    """Capture every configuration surface mutated by this QoS gate."""

    return {
        "firewall_mangle": _normalized_rows(
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
        "queue_simple": _normalized_rows(
            admin,
            "queue/simple",
            ("name", "target", "max-limit", "queue", "disabled"),
        ),
        "queue_tree": _normalized_rows(
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
        "queue_type": _normalized_rows(
            admin,
            "queue/type",
            ("name", "kind"),
        ),
    }


def _owned_objects_absent(admin: base.LoopbackCHRAdmin) -> bool:
    if any(
        str(row.get("comment") or "").startswith(COMMENT_PREFIX)
        for row in _records(admin, "ip/firewall/mangle")
    ):
        return False
    if any(
        str(row.get("name") or "").startswith("routercfg-qos-")
        for row in _records(admin, "queue/tree")
    ):
        return False
    if any(
        str(row.get("name") or "") == QUEUE_TYPE
        for row in _records(admin, "queue/type")
    ):
        return False
    return True


def _rollback_script() -> str:
    """Remove only objects created by this clean disposable-CHR gate."""

    return "\n".join(
        (
            f'/queue/tree/remove [find where parent="{PARENT_NAME}"]',
            f'/queue/tree/remove [find where name="{PARENT_NAME}"]',
            f'/ip/firewall/mangle/remove [find where comment~"^{COMMENT_PREFIX}"]',
            f'/queue/type/remove [find where name="{QUEUE_TYPE}"]',
        )
    ) + "\n"


def _reset_verdict(admin: base.LoopbackCHRAdmin) -> None:
    verdict_id = base._find_file_id(admin, VERDICT_FILE)
    if not verdict_id:
        raise CHRQoSBaselineError("QoS verdict file disappeared")
    admin.request("PATCH", f"file/{verdict_id}", {"contents": "PENDING"})


def _dry_run(
    admin: base.LoopbackCHRAdmin,
    *,
    apply_script: str,
    rollback_script: str,
) -> dict[str, Any]:
    before_digest = base._canonical_digest(_configuration_snapshot(admin))

    chunked._create_text_file_chunk_verified(admin, APPLY_FILE, apply_script)
    chunked._create_text_file_chunk_verified(admin, VERDICT_FILE, "PENDING")
    apply_result = base._execute_import_dry_run(
        admin,
        file_name=APPLY_FILE,
        verdict_name=VERDICT_FILE,
        expect_success=True,
    )

    chunked._create_text_file_chunk_verified(admin, ROLLBACK_FILE, rollback_script)
    _reset_verdict(admin)
    rollback_result = base._execute_import_dry_run(
        admin,
        file_name=ROLLBACK_FILE,
        verdict_name=VERDICT_FILE,
        expect_success=True,
    )

    after_digest = base._canonical_digest(_configuration_snapshot(admin))
    if after_digest != before_digest:
        raise CHRQoSBaselineError("QoS import dry-run changed RouterOS configuration")
    return {
        "apply": apply_result,
        "rollback": rollback_result,
        "configuration_unchanged": True,
        "configuration_sha256": before_digest,
    }


def _runtime_state(admin: base.LoopbackCHRAdmin) -> dict[str, Any]:
    queue_types = [
        row for row in _records(admin, "queue/type")
        if str(row.get("name") or "") == QUEUE_TYPE
    ]
    if len(queue_types) != 1:
        raise CHRQoSBaselineError(
            f"expected one managed FQ-CoDel queue type, observed {len(queue_types)}"
        )
    if str(queue_types[0].get("kind") or "").strip().lower() != "fq-codel":
        raise CHRQoSBaselineError("managed queue type is not fq-codel")

    mangle = [
        row for row in _records(admin, "ip/firewall/mangle")
        if str(row.get("comment") or "").startswith(COMMENT_PREFIX)
    ]
    if len(mangle) != 2:
        raise CHRQoSBaselineError(f"expected two managed QoS mangle rules, observed {len(mangle)}")
    if any(base._is_true(row.get("invalid")) or base._is_true(row.get("disabled")) for row in mangle):
        raise CHRQoSBaselineError("managed QoS mangle rule is invalid or disabled")

    by_comment = {str(row.get("comment") or ""): row for row in mangle}
    voice_comment = COMMENT_PREFIX + f"mark:{WAN_NAME}:voice:46"
    default_comment = COMMENT_PREFIX + f"mark:{WAN_NAME}:default"
    if set(by_comment) != {voice_comment, default_comment}:
        raise CHRQoSBaselineError(f"unexpected managed QoS mangle comments: {sorted(by_comment)}")

    voice = by_comment[voice_comment]
    default = by_comment[default_comment]
    if (
        str(voice.get("chain") or "") != "forward"
        or str(voice.get("out-interface") or "") != WAN_INTERFACE
        or str(voice.get("dscp") or "") != "46"
        or str(voice.get("action") or "") != "mark-packet"
        or str(voice.get("new-packet-mark") or "") != VOICE_NAME
    ):
        raise CHRQoSBaselineError("voice DSCP classifier does not match rendered policy")
    if (
        str(default.get("chain") or "") != "forward"
        or str(default.get("out-interface") or "") != WAN_INTERFACE
        or str(default.get("action") or "") != "mark-packet"
        or str(default.get("new-packet-mark") or "") != DEFAULT_NAME
    ):
        raise CHRQoSBaselineError("default classifier does not match rendered policy")

    trees = [
        row for row in _records(admin, "queue/tree")
        if str(row.get("name") or "").startswith("routercfg-qos-")
    ]
    if len(trees) != 3:
        raise CHRQoSBaselineError(f"expected three managed Queue Tree rows, observed {len(trees)}")
    if any(base._is_true(row.get("invalid")) or base._is_true(row.get("disabled")) for row in trees):
        raise CHRQoSBaselineError("managed Queue Tree row is invalid or disabled")

    by_name = {str(row.get("name") or ""): row for row in trees}
    if set(by_name) != {PARENT_NAME, VOICE_NAME, DEFAULT_NAME}:
        raise CHRQoSBaselineError(f"unexpected managed Queue Tree names: {sorted(by_name)}")
    parent = by_name[PARENT_NAME]
    if str(parent.get("parent") or "") != WAN_INTERFACE:
        raise CHRQoSBaselineError("QoS root Queue Tree is not attached to the explicit WAN interface")

    voice_leaf = by_name[VOICE_NAME]
    default_leaf = by_name[DEFAULT_NAME]
    for name, row, expected_priority in (
        (VOICE_NAME, voice_leaf, "1"),
        (DEFAULT_NAME, default_leaf, "8"),
    ):
        if (
            str(row.get("parent") or "") != PARENT_NAME
            or str(row.get("packet-mark") or "") != name
            or str(row.get("queue") or "") != QUEUE_TYPE
            or str(row.get("priority") or "") != expected_priority
        ):
            raise CHRQoSBaselineError(f"Queue Tree leaf {name!r} does not match rendered policy")

    # The loopback REST request itself is the management-survival assertion.
    admin.request("GET", "system/resource")
    return {
        "managed_queue_type_count": 1,
        "managed_mangle_count": 2,
        "managed_queue_tree_count": 3,
        "invalid_managed_objects": 0,
        "disabled_managed_objects": 0,
        "voice_dscp_46_exact": True,
        "default_class_exact": True,
        "queue_hierarchy_exact": True,
        "fq_codel_exact": True,
        "management_rest_reachable_after_apply": True,
        "throughput_or_latency_claimed": False,
    }


def verify_qos_baseline(*, admin_url: str) -> dict[str, Any]:
    admin = base.LoopbackCHRAdmin(admin_url)
    platform = admin.assert_disposable_chr()

    if not _owned_objects_absent(admin):
        raise CHRQoSBaselineError("disposable CHR baseline already contains routercfg-owned QoS objects")

    ir = _build_ir()
    live_state = _live_renderer_state(admin)
    plan = render_routeros_qos(ir=ir, state=live_state).as_dict()
    commands = plan.get("commands")
    if not isinstance(commands, list) or len(commands) != 6:
        raise CHRQoSBaselineError(
            f"QoS CHR fixture requires exactly six generated commands, observed {len(commands) if isinstance(commands, list) else 'invalid'}"
        )
    apply_script = "\n".join(str(item["command"]) for item in commands) + "\n"
    rollback_script = _rollback_script()

    for name in TEMP_FILES:
        base._delete_file_if_present(admin, name)

    baseline = _configuration_snapshot(admin)
    baseline_digest = base._canonical_digest(baseline)
    dry_run_result: dict[str, Any] | None = None
    apply_result: dict[str, Any] | None = None
    rollback_result: dict[str, Any] | None = None
    runtime: dict[str, Any] | None = None
    mutated_digest: str | None = None
    rollback_digest: str | None = None

    try:
        dry_run_result = _dry_run(
            admin,
            apply_script=apply_script,
            rollback_script=rollback_script,
        )

        chunked._create_text_file_chunk_verified(admin, APPLY_FILE, apply_script)
        apply_result = mutation._execute_import(admin, file_name=APPLY_FILE, expect_success=True)
        mutated_digest = base._canonical_digest(_configuration_snapshot(admin))
        if mutated_digest == baseline_digest:
            raise CHRQoSBaselineError("QoS apply did not change the configuration digest")
        runtime = _runtime_state(admin)

        chunked._create_text_file_chunk_verified(admin, ROLLBACK_FILE, rollback_script)
        rollback_result = mutation._execute_import(admin, file_name=ROLLBACK_FILE, expect_success=True)
        if not _owned_objects_absent(admin):
            raise CHRQoSBaselineError("routercfg-owned QoS objects remain after rollback")
        rollback_digest = base._canonical_digest(_configuration_snapshot(admin))
        if rollback_digest != baseline_digest:
            raise CHRQoSBaselineError("QoS rollback did not restore the exact baseline digest")
    finally:
        for name in TEMP_FILES:
            base._delete_file_if_present(admin, name)
        base._assert_files_absent(admin, TEMP_FILES)

    return {
        "ok": True,
        "acceptance": "PASS",
        "scope": "disposable_chr_qos_runtime_and_rollback",
        "platform": {
            "version": str(platform.get("version") or ""),
            "architecture": str(platform.get("architecture-name") or ""),
            "board_name": str(platform.get("board-name") or ""),
        },
        "fixture": {
            "kind": "lab_only_explicit_qos_policy",
            "wan_interface": WAN_INTERFACE,
            "egress_limit_mbps": 100,
            "voice_dscp": [46],
            "command_count": len(commands),
        },
        "renderer_input": {
            "live_conflict_surfaces_observed": True,
            "synthetic_live_state_used": False,
            "source_ir_sha256": str(plan.get("source_ir_sha256") or ""),
            "plan_sha256": str(plan.get("plan_sha256") or ""),
        },
        "dry_run": dry_run_result,
        "apply": apply_result,
        "runtime": runtime,
        "rollback": rollback_result,
        "configuration_baseline_sha256": baseline_digest,
        "configuration_mutated_sha256": mutated_digest,
        "configuration_rollback_sha256": rollback_digest,
        "rollback_digest_restored": rollback_digest == baseline_digest,
        "temporary_files_removed": True,
        "production_writer_available": False,
        "transport_exposed_to_product": False,
        "write_authorized": False,
        "physical_router_targeted": False,
        "throughput_or_latency_acceptance": False,
    }


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Validate RouterOS QoS generation on disposable official CHR"
    )
    parser.add_argument("--admin-url", default="http://127.0.0.1:9580")
    parser.add_argument("--output", required=True)
    args = parser.parse_args()

    output = Path(args.output)
    output.parent.mkdir(parents=True, exist_ok=True)
    try:
        result = verify_qos_baseline(admin_url=args.admin_url)
        rc = 0
    except (OSError, base.CHRRenderDryRunError, mutation.CHRMutationRollbackError, CHRQoSBaselineError) as exc:
        result = {
            "ok": False,
            "acceptance": "FAIL",
            "error": str(exc),
            "production_writer_available": False,
            "transport_exposed_to_product": False,
            "write_authorized": False,
            "physical_router_targeted": False,
            "throughput_or_latency_acceptance": False,
        }
        rc = 15

    output.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(json.dumps(result, indent=2, sort_keys=True))
    return rc


if __name__ == "__main__":
    raise SystemExit(main())
