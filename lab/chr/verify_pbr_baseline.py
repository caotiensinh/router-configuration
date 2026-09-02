from __future__ import annotations

import argparse
import ipaddress
import json
from pathlib import Path
from typing import Any, Mapping

import verify_mutation_rollback as mutation
import verify_render_dry_run as base
import verify_render_dry_run_chunked as chunked
from router_configuration.routeros_pbr_renderer import render_routeros_pbr
from router_configuration.safe_subset_ir import IntentOperation, IntentRisk, SafeSubsetIR


class CHRPbrBaselineError(RuntimeError):
    pass


APPLY_FILE = "routercfg-pbr-apply.rsc"
ROLLBACK_FILE = "routercfg-pbr-rollback.rsc"
VERDICT_FILE = "routercfg-pbr-verdict.txt"
TEMP_FILES = (APPLY_FILE, ROLLBACK_FILE, VERDICT_FILE, mutation.VERDICT_FILE)
TABLE_NAME = "routercfg-pbr-lab-table"
RULE_NAME = "lab-source-steering"
RULE_COMMENT = f"routercfg:managed:pbr:{RULE_NAME}"
SOURCE_CIDR = "198.51.100.0/24"
DESTINATION_CIDR = "0.0.0.0/0"


def _records(admin: base.LoopbackCHRAdmin, path: str) -> list[Mapping[str, Any]]:
    _, payload = admin.request("GET", path)
    return list(base._rows(payload))


def _observed_management_network(admin: base.LoopbackCHRAdmin) -> str:
    candidates: list[tuple[int, str]] = []
    for row in _records(admin, "ip/address"):
        if str(row.get("interface") or "") != "ether1":
            continue
        try:
            interface = ipaddress.ip_interface(str(row.get("address") or ""))
        except ValueError:
            continue
        if interface.version != 4 or interface.ip.is_loopback or interface.ip.is_unspecified:
            continue
        if interface.network.prefixlen == 0 or interface.network.prefixlen >= 31:
            continue
        candidates.append((interface.network.prefixlen, str(interface.network)))
    if not candidates:
        raise CHRPbrBaselineError("disposable CHR ether1 has no usable bounded management network")
    candidates.sort(key=lambda item: (-item[0], item[1]))
    return candidates[0][1]


def _find_table(admin: base.LoopbackCHRAdmin) -> Mapping[str, Any] | None:
    return next(
        (
            row
            for row in _records(admin, "routing/table")
            if str(row.get("name") or "") == TABLE_NAME
        ),
        None,
    )


def _create_lab_table(admin: base.LoopbackCHRAdmin) -> str:
    if _find_table(admin) is not None:
        raise CHRPbrBaselineError("disposable CHR unexpectedly already contains the PBR lab table")
    _, created = admin.request("PUT", "routing/table", {"name": TABLE_NAME, "fib": True})
    table_id = str(created.get(".id") or "").strip() if isinstance(created, Mapping) else ""
    row = _find_table(admin)
    if row is None:
        raise CHRPbrBaselineError("CHR did not expose the created PBR lab routing table")
    table_id = table_id or str(row.get(".id") or "").strip()
    if not table_id:
        raise CHRPbrBaselineError("PBR lab routing table has no RouterOS id")
    return table_id


def _remove_lab_table(admin: base.LoopbackCHRAdmin, table_id: str) -> None:
    if table_id:
        admin.request("DELETE", f"routing/table/{table_id}")
    if _find_table(admin) is not None:
        raise CHRPbrBaselineError("temporary PBR lab routing table was not removed")


def _build_ir(management_network: str) -> dict[str, Any]:
    return SafeSubsetIR(
        device_id="chr-pbr-baseline-lab",
        operations=(
            IntentOperation(
                operation_id="security.baseline",
                feature="security",
                resource="firewall_baseline",
                attributes={
                    "profile": "enterprise_baseline",
                    "wan_input_default": "deny",
                    "management_from_wan": False,
                    "management_sources": [management_network],
                    "anti_spoofing": True,
                    "icmp_policy": "essential_ipv4",
                    "required_wan_services": [],
                },
                risk=IntentRisk.HIGH,
                requires=("firewall", "management_path"),
            ),
            IntentOperation(
                operation_id="routing.pbr",
                feature="pbr",
                resource="policy_routing_rules",
                attributes={
                    "strategy": "routing_rules",
                    "mangle_routing_marks": False,
                    "rules": [
                        {
                            "name": RULE_NAME,
                            "source_cidr": SOURCE_CIDR,
                            "destination_cidr": DESTINATION_CIDR,
                            "table": TABLE_NAME,
                            "action": "lookup_only",
                        }
                    ],
                },
                risk=IntentRisk.HIGH,
                requires=("routing", "management_path"),
            ),
        ),
    ).as_dict()


def _renderer_inputs(admin: base.LoopbackCHRAdmin) -> tuple[dict[str, Any], dict[str, Any]]:
    routing_tables = [dict(row) for row in _records(admin, "routing/table")]
    routing_rules = [dict(row) for row in _records(admin, "routing/rule")]
    state = {"routing_tables": routing_tables}
    prerequisites = {
        "schema_version": "routeros-render-prerequisites/1",
        "policy_routing": {"rules": routing_rules},
    }
    return state, prerequisites


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
    return {
        "routing_tables": _normalized_rows(
            admin,
            "routing/table",
            ("name", "fib", "disabled"),
        ),
        "routing_rules": _normalized_rows(
            admin,
            "routing/rule",
            (
                "src-address",
                "dst-address",
                "action",
                "table",
                "interface",
                "comment",
                "disabled",
            ),
        ),
    }


def _owned_rule_absent(admin: base.LoopbackCHRAdmin) -> bool:
    return not any(
        str(row.get("comment") or "") == RULE_COMMENT
        for row in _records(admin, "routing/rule")
    )


def _rollback_script() -> str:
    return f'/routing/rule/remove [find where comment="{RULE_COMMENT}"]\n'


def _reset_verdict(admin: base.LoopbackCHRAdmin) -> None:
    verdict_id = base._find_file_id(admin, VERDICT_FILE)
    if not verdict_id:
        raise CHRPbrBaselineError("PBR verdict file disappeared")
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
        raise CHRPbrBaselineError("PBR import dry-run changed RouterOS configuration")
    return {
        "apply": apply_result,
        "rollback": rollback_result,
        "configuration_unchanged": True,
        "configuration_sha256": before_digest,
    }


def _runtime_state(admin: base.LoopbackCHRAdmin) -> dict[str, Any]:
    rows = [
        row for row in _records(admin, "routing/rule")
        if str(row.get("comment") or "") == RULE_COMMENT
    ]
    if len(rows) != 1:
        raise CHRPbrBaselineError(f"expected one managed PBR routing rule, observed {len(rows)}")
    rule = rows[0]
    if base._is_true(rule.get("invalid")) or base._is_true(rule.get("disabled")):
        raise CHRPbrBaselineError("managed PBR routing rule is invalid or disabled")
    if (
        str(rule.get("src-address") or "") != SOURCE_CIDR
        or str(rule.get("dst-address") or "") != DESTINATION_CIDR
        or str(rule.get("action") or "") != "lookup-only-in-table"
        or str(rule.get("table") or "") != TABLE_NAME
    ):
        raise CHRPbrBaselineError("managed PBR routing rule does not match the explicit policy")

    table = _find_table(admin)
    if table is None or str(table.get("name") or "") != TABLE_NAME:
        raise CHRPbrBaselineError("PBR lab routing table disappeared during runtime validation")

    admin.request("GET", "system/resource")
    return {
        "managed_rule_count": 1,
        "invalid_managed_rules": 0,
        "disabled_managed_rules": 0,
        "source_cidr_exact": True,
        "destination_cidr_exact": True,
        "lookup_only_in_table_exact": True,
        "table_reference_exact": True,
        "mangle_routing_marks_used": False,
        "management_rest_reachable_after_apply": True,
        "route_selection_data_plane_claimed": False,
    }


def verify_pbr_baseline(*, admin_url: str) -> dict[str, Any]:
    admin = base.LoopbackCHRAdmin(admin_url)
    platform = admin.assert_disposable_chr()
    if not _owned_rule_absent(admin):
        raise CHRPbrBaselineError("disposable CHR baseline already contains the managed PBR rule")

    original_digest = base._canonical_digest(_configuration_snapshot(admin))
    table_id = ""
    setup_digest: str | None = None
    mutated_digest: str | None = None
    rollback_digest: str | None = None
    cleanup_digest: str | None = None
    dry_run_result: dict[str, Any] | None = None
    apply_result: dict[str, Any] | None = None
    rollback_result: dict[str, Any] | None = None
    runtime: dict[str, Any] | None = None
    plan: Mapping[str, Any] | None = None

    try:
        table_id = _create_lab_table(admin)
        setup_digest = base._canonical_digest(_configuration_snapshot(admin))
        if setup_digest == original_digest:
            raise CHRPbrBaselineError("PBR lab setup did not create the required routing table")

        management_network = _observed_management_network(admin)
        ir = _build_ir(management_network)
        state, prerequisites = _renderer_inputs(admin)
        plan = render_routeros_pbr(
            ir=ir,
            state=state,
            prerequisites=prerequisites,
        ).as_dict()
        commands = plan.get("commands")
        if not isinstance(commands, list) or len(commands) != 1:
            raise CHRPbrBaselineError("PBR CHR fixture requires exactly one generated routing-rule command")
        apply_script = str(commands[0]["command"]) + "\n"
        rollback_script = _rollback_script()

        for name in TEMP_FILES:
            base._delete_file_if_present(admin, name)
        dry_run_result = _dry_run(
            admin,
            apply_script=apply_script,
            rollback_script=rollback_script,
        )

        chunked._create_text_file_chunk_verified(admin, APPLY_FILE, apply_script)
        apply_result = mutation._execute_import(admin, file_name=APPLY_FILE, expect_success=True)
        mutated_digest = base._canonical_digest(_configuration_snapshot(admin))
        if mutated_digest == setup_digest:
            raise CHRPbrBaselineError("PBR apply did not change the configuration digest")
        runtime = _runtime_state(admin)

        chunked._create_text_file_chunk_verified(admin, ROLLBACK_FILE, rollback_script)
        rollback_result = mutation._execute_import(admin, file_name=ROLLBACK_FILE, expect_success=True)
        if not _owned_rule_absent(admin):
            raise CHRPbrBaselineError("managed PBR routing rule remains after rollback")
        rollback_digest = base._canonical_digest(_configuration_snapshot(admin))
        if rollback_digest != setup_digest:
            raise CHRPbrBaselineError("PBR rollback did not restore the exact post-setup baseline")
    finally:
        for name in TEMP_FILES:
            base._delete_file_if_present(admin, name)
        base._assert_files_absent(admin, TEMP_FILES)
        if table_id:
            _remove_lab_table(admin, table_id)
        cleanup_digest = base._canonical_digest(_configuration_snapshot(admin))

    if cleanup_digest != original_digest:
        raise CHRPbrBaselineError("PBR lab setup cleanup did not restore the original baseline")

    assert plan is not None
    return {
        "ok": True,
        "acceptance": "PASS",
        "scope": "disposable_chr_pbr_rule_runtime_and_rollback",
        "platform": {
            "version": str(platform.get("version") or ""),
            "architecture": str(platform.get("architecture-name") or ""),
            "board_name": str(platform.get("board-name") or ""),
        },
        "fixture": {
            "kind": "lab_only_rfc5737_source_policy",
            "source_cidr": SOURCE_CIDR,
            "destination_cidr": DESTINATION_CIDR,
            "table": TABLE_NAME,
            "command_count": 1,
        },
        "renderer_input": {
            "management_network_source": "live_chr_ether1",
            "routing_tables_source": "live_chr",
            "routing_rules_source": "live_chr",
            "plan_sha256": str(plan.get("plan_sha256") or ""),
        },
        "lab_setup": {
            "routing_table_created": True,
            "routing_table_removed": True,
            "write_operations_performed": True,
        },
        "dry_run": dry_run_result,
        "apply": apply_result,
        "runtime": runtime,
        "rollback": rollback_result,
        "configuration_original_sha256": original_digest,
        "configuration_setup_sha256": setup_digest,
        "configuration_mutated_sha256": mutated_digest,
        "configuration_rollback_sha256": rollback_digest,
        "configuration_cleanup_sha256": cleanup_digest,
        "rollback_digest_restored": rollback_digest == setup_digest,
        "lab_setup_cleanup_restored": cleanup_digest == original_digest,
        "temporary_files_removed": True,
        "route_selection_data_plane_acceptance": False,
        "production_writer_available": False,
        "transport_exposed_to_product": False,
        "write_authorized": False,
        "physical_router_targeted": False,
    }


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Validate RouterOS PBR routing-rule generation on disposable official CHR"
    )
    parser.add_argument("--admin-url", default="http://127.0.0.1:9680")
    parser.add_argument("--output", required=True)
    args = parser.parse_args()

    output = Path(args.output)
    output.parent.mkdir(parents=True, exist_ok=True)
    try:
        result = verify_pbr_baseline(admin_url=args.admin_url)
        rc = 0
    except (OSError, base.CHRRenderDryRunError, mutation.CHRMutationRollbackError, CHRPbrBaselineError) as exc:
        result = {
            "ok": False,
            "acceptance": "FAIL",
            "error": str(exc),
            "route_selection_data_plane_acceptance": False,
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
