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


class CHRQoSRuntimeError(RuntimeError):
    pass


APPLY_FILE = "routercfg-qos-parent-default-apply.rsc"
ROLLBACK_FILE = "routercfg-qos-parent-default-rollback.rsc"
TEMP_FILES = (APPLY_FILE, ROLLBACK_FILE, mutation.VERDICT_FILE)


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


def _snapshot(admin: base.LoopbackCHRAdmin) -> dict[str, Any]:
    return {
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
        "device_id": "chr-qos-runtime",
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
                    "addressing": "isp_defined",
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


def _render() -> dict[str, Any]:
    plan = render_routeros_qos(ir=_runtime_ir()).as_dict()
    if plan.get("strategy") != "parent_fq_codel_default_only_marked_priority_child":
        raise CHRQoSRuntimeError("production renderer returned an unexpected QoS strategy")
    if plan.get("default_traffic_marked") is not False:
        raise CHRQoSRuntimeError("production renderer unexpectedly marks default traffic")
    if any(
        plan.get(field) is not expected
        for field, expected in (
            ("secrets_resolved", False),
            ("transport_present", False),
            ("apply_available", False),
            ("write_authorized", False),
        )
    ):
        raise CHRQoSRuntimeError("production renderer violated the generation-only safety boundary")
    targets = plan.get("targets")
    commands = plan.get("commands")
    if not isinstance(targets, list) or len(targets) != 1:
        raise CHRQoSRuntimeError("runtime fixture requires exactly one rendered QoS target")
    if not isinstance(commands, list) or len(commands) != 4:
        raise CHRQoSRuntimeError("runtime fixture requires exactly four production renderer commands")
    target = targets[0]
    if not isinstance(target, Mapping):
        raise CHRQoSRuntimeError("rendered QoS target must be an object")
    if target.get("interface") != "ether2" or target.get("capacity_mbps") != 100:
        raise CHRQoSRuntimeError("production renderer did not preserve the disposable CHR target facts")
    if target.get("reserve_mbps") != 10:
        raise CHRQoSRuntimeError("production renderer did not preserve the 10 percent reserve contract")
    return plan


def _script_from_plan(plan: Mapping[str, Any]) -> str:
    rows = plan.get("commands")
    if not isinstance(rows, list):
        raise CHRQoSRuntimeError("rendered QoS commands must be a list")
    commands: list[str] = []
    for row in rows:
        if not isinstance(row, Mapping):
            raise CHRQoSRuntimeError("rendered QoS command row must be an object")
        command = str(row.get("command") or "").strip()
        if not command:
            raise CHRQoSRuntimeError("rendered QoS command must not be empty")
        commands.append(command)
    return "\n".join(commands) + "\n"


def _rollback_script(plan: Mapping[str, Any]) -> str:
    targets = plan.get("targets")
    queue_type = plan.get("queue_type")
    if not isinstance(targets, list) or len(targets) != 1 or not isinstance(queue_type, Mapping):
        raise CHRQoSRuntimeError("rendered QoS plan cannot build an owned-only rollback")
    target = targets[0]
    if not isinstance(target, Mapping):
        raise CHRQoSRuntimeError("rendered QoS target must be an object")
    parent = str(target.get("parent_queue") or "")
    child = str(target.get("priority_queue") or "")
    comment = str(target.get("comment") or "")
    qtype = str(queue_type.get("name") or "")
    if not all((parent, child, comment, qtype)):
        raise CHRQoSRuntimeError("rendered QoS ownership identifiers are incomplete")
    return "\n".join(
        (
            f'/queue/tree/remove [find where name="{child}"]',
            f'/queue/tree/remove [find where name="{parent}"]',
            f'/ip/firewall/mangle/remove [find where comment="{comment}"]',
            f'/queue/type/remove [find where name="{qtype}"]',
        )
    ) + "\n"


def _one(rows: list[Mapping[str, Any]], *, label: str, predicate) -> Mapping[str, Any]:
    matches = [row for row in rows if predicate(row)]
    if len(matches) != 1:
        raise CHRQoSRuntimeError(f"expected exactly one {label}, observed {len(matches)}")
    return matches[0]


def _assert_owned_surfaces_absent(admin: base.LoopbackCHRAdmin, plan: Mapping[str, Any]) -> None:
    target = plan["targets"][0]
    queue_type = plan["queue_type"]
    comment = str(target["comment"])
    parent = str(target["parent_queue"])
    child = str(target["priority_queue"])
    qtype = str(queue_type["name"])
    if any(str(row.get("comment") or "") == comment for row in _records(admin, "ip/firewall/mangle")):
        raise CHRQoSRuntimeError("disposable CHR baseline already contains the managed QoS mangle object")
    if any(str(row.get("name") or "") in {parent, child} for row in _records(admin, "queue/tree")):
        raise CHRQoSRuntimeError("disposable CHR baseline already contains a managed QoS queue tree")
    if any(str(row.get("name") or "") == qtype for row in _records(admin, "queue/type")):
        raise CHRQoSRuntimeError("disposable CHR baseline already contains the managed QoS queue type")


def verify(*, admin_url: str) -> dict[str, Any]:
    admin = base.LoopbackCHRAdmin(admin_url)
    platform = admin.assert_disposable_chr()
    interfaces = {str(row.get("name") or "") for row in _records(admin, "interface")}
    if not {"ether1", "ether2"}.issubset(interfaces):
        raise CHRQoSRuntimeError("QoS runtime requires disposable CHR ether1 management and ether2 test WAN")

    plan = _render()
    _assert_owned_surfaces_absent(admin, plan)
    baseline_sha = base._canonical_digest(_snapshot(admin))
    for name in TEMP_FILES:
        base._delete_file_if_present(admin, name)

    target = plan["targets"][0]
    queue_type = plan["queue_type"]
    comment = str(target["comment"])
    parent_name = str(target["parent_queue"])
    child_name = str(target["priority_queue"])
    mark_name = str(target["packet_mark"])
    qtype_name = str(queue_type["name"])
    mutated_sha = None
    rollback_sha = None
    apply_result: Mapping[str, Any] | None = None
    rollback_result: Mapping[str, Any] | None = None
    try:
        chunked._create_text_file_chunk_verified(admin, APPLY_FILE, _script_from_plan(plan))
        apply_result = mutation._execute_import(admin, file_name=APPLY_FILE, expect_success=True)

        mangle = _one(
            _records(admin, "ip/firewall/mangle"),
            label="managed EF mangle",
            predicate=lambda row: str(row.get("comment") or "") == comment,
        )
        trees = _records(admin, "queue/tree")
        parent = _one(
            trees,
            label="managed parent queue",
            predicate=lambda row: str(row.get("name") or "") == parent_name,
        )
        child = _one(
            trees,
            label="managed EF child queue",
            predicate=lambda row: str(row.get("name") or "") == child_name,
        )
        qtype = _one(
            _records(admin, "queue/type"),
            label="managed FQ-CoDel queue type",
            predicate=lambda row: str(row.get("name") or "") == qtype_name,
        )

        managed = (mangle, parent, child)
        invalid = sum(1 for row in managed if base._is_true(row.get("invalid")))
        disabled = sum(1 for row in managed if base._is_true(row.get("disabled")))
        if invalid or disabled:
            raise CHRQoSRuntimeError(
                f"production QoS formulation is not runtime-valid: invalid={invalid} disabled={disabled}"
            )
        if str(qtype.get("kind") or "").lower() != "fq-codel":
            raise CHRQoSRuntimeError("managed queue type is not fq-codel")
        if str(mangle.get("out-interface") or "") != "ether2":
            raise CHRQoSRuntimeError("managed EF mangle did not bind the rendered egress interface")
        if str(mangle.get("dscp") or "") != "46":
            raise CHRQoSRuntimeError("managed EF mangle did not retain DSCP 46")
        if str(mangle.get("new-packet-mark") or "") != mark_name:
            raise CHRQoSRuntimeError("managed EF mangle did not retain the rendered packet mark")
        if str(parent.get("parent") or "") != "ether2":
            raise CHRQoSRuntimeError("parent queue did not retain the rendered egress interface")
        if str(parent.get("queue") or "") != qtype_name:
            raise CHRQoSRuntimeError("parent queue did not retain FQ-CoDel")
        if str(child.get("parent") or "") != parent_name:
            raise CHRQoSRuntimeError("EF child queue did not retain the rendered parent")
        if str(child.get("packet-mark") or "") != mark_name:
            raise CHRQoSRuntimeError("EF child queue did not retain the rendered packet mark")
        if str(child.get("priority") or "") != "1":
            raise CHRQoSRuntimeError("EF child queue did not retain priority 1")

        managed_mangle = [
            row
            for row in _records(admin, "ip/firewall/mangle")
            if str(row.get("comment") or "").startswith("routercfg:managed:qos:")
        ]
        if len(managed_mangle) != 1:
            raise CHRQoSRuntimeError("production QoS runtime must create exactly one managed mangle rule per target")
        default_mangle = [
            row for row in managed_mangle if "default" in str(row.get("comment") or "").lower()
        ]
        if default_mangle:
            raise CHRQoSRuntimeError("production QoS runtime unexpectedly created a default traffic mangle rule")

        mutated_sha = base._canonical_digest(_snapshot(admin))
        if mutated_sha == baseline_sha:
            raise CHRQoSRuntimeError("production QoS apply did not change the configuration digest")

        chunked._create_text_file_chunk_verified(admin, ROLLBACK_FILE, _rollback_script(plan))
        rollback_result = mutation._execute_import(admin, file_name=ROLLBACK_FILE, expect_success=True)
        rollback_sha = base._canonical_digest(_snapshot(admin))
        if rollback_sha != baseline_sha:
            raise CHRQoSRuntimeError("QoS rollback did not restore the exact baseline digest")
    finally:
        for name in TEMP_FILES:
            base._delete_file_if_present(admin, name)

    return {
        "ok": True,
        "acceptance": "PASS",
        "scope": "production_renderer_runtime_validity_and_exact_owned_rollback",
        "strategy": str(plan["strategy"]),
        "platform": {
            "version": str(platform.get("version") or ""),
            "architecture": str(platform.get("architecture-name") or ""),
            "board_name": str(platform.get("board-name") or ""),
        },
        "renderer": {
            "production_renderer_used": True,
            "schema_version": str(plan["schema_version"]),
            "source_ir_sha256": str(plan["source_ir_sha256"]),
            "render_sha256": str(plan["render_sha256"]),
            "command_count": len(plan["commands"]),
            "default_traffic_marked": bool(plan["default_traffic_marked"]),
        },
        "runtime": {
            "managed_mangle_count": 1,
            "managed_queue_tree_count": 2,
            "managed_queue_type_count": 1,
            "invalid_managed_objects": 0,
            "disabled_managed_objects": 0,
            "default_mangle_count": 0,
            "parent_queue_kind": "fq-codel",
            "latency_dscp": 46,
            "latency_priority": 1,
            "reserve_percent": 10,
        },
        "apply": dict(apply_result or {}),
        "rollback": dict(rollback_result or {}),
        "configuration_baseline_sha256": baseline_sha,
        "configuration_mutated_sha256": mutated_sha,
        "configuration_rollback_sha256": rollback_sha,
        "rollback_digest_restored": rollback_sha == baseline_sha,
        "packet_flow_acceptance": False,
        "latency_performance_claimed": False,
        "production_writer_available": False,
        "transport_exposed_to_product": False,
        "write_authorized": False,
        "physical_router_targeted": False,
    }


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Validate production parent-default QoS renderer on disposable RouterOS CHR"
    )
    parser.add_argument("--admin-url", required=True)
    parser.add_argument("--output", required=True)
    args = parser.parse_args()

    result = verify(admin_url=args.admin_url)
    output = Path(args.output)
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
