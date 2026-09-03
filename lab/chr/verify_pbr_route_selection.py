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


class CHRPbrRouteSelectionError(RuntimeError):
    pass


TABLE_NAME = "routercfg-pbr-dp-table"
RULE_NAME = "route-selection-data-plane"
RULE_COMMENT = f"routercfg:managed:pbr:{RULE_NAME}"
LAB_PREFIX = "routercfg:lab:pbr-dp:"
SERVICE_IP = "203.0.113.100"
SERVICE_CIDR = f"{SERVICE_IP}/32"
SOURCE_CIDR = "10.10.10.0/24"
SETUP_FILE = "routercfg-pbr-dp-setup.rsc"
APPLY_FILE = "routercfg-pbr-dp-apply.rsc"
ROLLBACK_FILE = "routercfg-pbr-dp-rollback.rsc"
CLEANUP_FILE = "routercfg-pbr-dp-cleanup.rsc"
TEMP_FILES = (SETUP_FILE, APPLY_FILE, ROLLBACK_FILE, CLEANUP_FILE, mutation.VERDICT_FILE)


def _records(admin: base.LoopbackCHRAdmin, path: str) -> list[Mapping[str, Any]]:
    _, payload = admin.request("GET", path)
    return list(base._rows(payload))


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
        "ip_addresses": _normalized_rows(
            admin,
            "ip/address",
            ("address", "interface", "comment", "disabled"),
        ),
        "routing_tables": _normalized_rows(
            admin,
            "routing/table",
            ("name", "fib", "disabled"),
        ),
        "ip_routes": _normalized_rows(
            admin,
            "ip/route",
            ("dst-address", "gateway", "routing-table", "distance", "comment", "disabled"),
        ),
        "routing_rules": _normalized_rows(
            admin,
            "routing/rule",
            ("src-address", "dst-address", "action", "table", "interface", "comment", "disabled"),
        ),
    }


def _delete_temp_files(admin: base.LoopbackCHRAdmin) -> None:
    for name in TEMP_FILES:
        base._delete_file_if_present(admin, name)


def _execute_script(admin: base.LoopbackCHRAdmin, *, file_name: str, script: str) -> dict[str, Any]:
    base._delete_file_if_present(admin, file_name)
    base._delete_file_if_present(admin, mutation.VERDICT_FILE)
    chunked._create_text_file_chunk_verified(admin, file_name, script)
    try:
        return mutation._execute_import(admin, file_name=file_name, expect_success=True)
    finally:
        base._delete_file_if_present(admin, file_name)
        base._delete_file_if_present(admin, mutation.VERDICT_FILE)


def _setup_script() -> str:
    return "\n".join(
        (
            f'/ip/address/add address="192.0.2.2/30" interface=ether2 comment="{LAB_PREFIX}address:main"',
            f'/ip/address/add address="198.51.100.2/30" interface=ether3 comment="{LAB_PREFIX}address:pbr"',
            f'/ip/address/add address="10.10.10.1/24" interface=ether4 comment="{LAB_PREFIX}address:core"',
            f'/routing/table/add name="{TABLE_NAME}" fib',
            f'/ip/route/add dst-address="{SERVICE_CIDR}" gateway="192.0.2.1" comment="{LAB_PREFIX}route:main"',
            f'/ip/route/add dst-address="{SERVICE_CIDR}" gateway="198.51.100.1@main" routing-table="{TABLE_NAME}" comment="{LAB_PREFIX}route:pbr"',
        )
    ) + "\n"


def _cleanup_script() -> str:
    return "\n".join(
        (
            f'/routing/rule/remove [find where comment="{RULE_COMMENT}"]',
            f'/ip/route/remove [find where comment~"^{LAB_PREFIX}route:"]',
            f'/ip/address/remove [find where comment~"^{LAB_PREFIX}address:"]',
            f'/routing/table/remove [find where name="{TABLE_NAME}"]',
        )
    ) + "\n"


def _rollback_rule_script() -> str:
    return f'/routing/rule/remove [find where comment="{RULE_COMMENT}"]\n'


def _management_network(admin: base.LoopbackCHRAdmin) -> str:
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
        raise CHRPbrRouteSelectionError("disposable CHR ether1 has no bounded management network")
    candidates.sort(key=lambda item: (-item[0], item[1]))
    return candidates[0][1]


def _build_ir(management_network: str) -> dict[str, Any]:
    return SafeSubsetIR(
        device_id="chr-pbr-route-selection-lab",
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
                            "destination_cidr": SERVICE_CIDR,
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


def _render_plan(admin: base.LoopbackCHRAdmin) -> dict[str, Any]:
    state = {"routing_tables": [dict(row) for row in _records(admin, "routing/table")]}
    prerequisites = {
        "schema_version": "routeros-render-prerequisites/1",
        "policy_routing": {"rules": [dict(row) for row in _records(admin, "routing/rule")]},
    }
    return render_routeros_pbr(
        ir=_build_ir(_management_network(admin)),
        state=state,
        prerequisites=prerequisites,
    ).as_dict()


def _rule_rows(admin: base.LoopbackCHRAdmin) -> list[Mapping[str, Any]]:
    return [
        row
        for row in _records(admin, "routing/rule")
        if str(row.get("comment") or "") == RULE_COMMENT
    ]


def _assert_rule_absent(admin: base.LoopbackCHRAdmin) -> None:
    if _rule_rows(admin):
        raise CHRPbrRouteSelectionError("managed PBR rule unexpectedly exists")


def _assert_rule_active(admin: base.LoopbackCHRAdmin) -> dict[str, Any]:
    rows = _rule_rows(admin)
    if len(rows) != 1:
        raise CHRPbrRouteSelectionError(f"expected one managed PBR rule, observed {len(rows)}")
    row = rows[0]
    if base._is_true(row.get("invalid")) or base._is_true(row.get("disabled")):
        raise CHRPbrRouteSelectionError("managed PBR rule is invalid or disabled")
    expected = {
        "src-address": SOURCE_CIDR,
        "dst-address": SERVICE_CIDR,
        "action": "lookup-only-in-table",
        "table": TABLE_NAME,
    }
    observed = {key: str(row.get(key) or "") for key in expected}
    if observed != expected:
        raise CHRPbrRouteSelectionError(f"managed PBR rule mismatch: expected={expected} observed={observed}")
    return {
        "managed_rule_count": 1,
        "invalid_managed_rules": 0,
        "disabled_managed_rules": 0,
        "source_cidr_exact": True,
        "destination_cidr_exact": True,
        "lookup_only_in_table_exact": True,
        "table_reference_exact": True,
    }


def _load(path: str) -> dict[str, Any]:
    return json.loads(Path(path).read_text(encoding="utf-8"))


def _assert_flow(payload: Mapping[str, Any], expected_tag: str) -> dict[str, Any]:
    requested = int(payload.get("requested_flows") or 0)
    successful = int(payload.get("successful_flows") or 0)
    tags = payload.get("tags")
    if requested <= 0 or successful != requested or not isinstance(tags, Mapping):
        raise CHRPbrRouteSelectionError(
            f"packet-flow phase did not complete all probes: requested={requested} successful={successful}"
        )
    normalized_tags = {str(key): int(value) for key, value in tags.items()}
    if normalized_tags != {expected_tag: requested}:
        raise CHRPbrRouteSelectionError(
            f"packet-flow tag mismatch: expected={{{expected_tag!r}: {requested}}} observed={normalized_tags}"
        )
    return {
        "requested_flows": requested,
        "successful_flows": successful,
        "success_ratio": 1.0,
        "expected_tag": expected_tag,
        "observed_tags": normalized_tags,
    }


def prepare(*, admin_url: str, workflow_sha: str) -> dict[str, Any]:
    admin = base.LoopbackCHRAdmin(admin_url)
    platform = admin.assert_disposable_chr()
    _delete_temp_files(admin)
    _assert_rule_absent(admin)
    baseline_digest = base._canonical_digest(_configuration_snapshot(admin))
    _execute_script(admin, file_name=SETUP_FILE, script=_setup_script())
    setup_digest = base._canonical_digest(_configuration_snapshot(admin))
    if setup_digest == baseline_digest:
        raise CHRPbrRouteSelectionError("PBR data-plane lab setup did not change configuration")
    plan = _render_plan(admin)
    commands = plan.get("commands")
    if not isinstance(commands, list) or len(commands) != 1:
        raise CHRPbrRouteSelectionError("PBR route-selection gate requires exactly one production-renderer rule")
    return {
        "ok": True,
        "acceptance": "PREPARED",
        "workflow_sha": workflow_sha,
        "platform": {
            "version": str(platform.get("version") or ""),
            "architecture": str(platform.get("architecture-name") or ""),
            "board_name": str(platform.get("board-name") or ""),
        },
        "topology": {
            "core_cidr": SOURCE_CIDR,
            "main_link": "192.0.2.0/30",
            "pbr_link": "198.51.100.0/30",
            "service_ip": SERVICE_IP,
            "main_tag": "MAIN",
            "pbr_tag": "PBR",
        },
        "renderer": {
            "production_renderer_used": True,
            "schema_version": str(plan.get("schema_version") or ""),
            "strategy": str(plan.get("strategy") or ""),
            "plan_sha256": str(plan.get("plan_sha256") or ""),
            "command_count": 1,
        },
        "configuration_baseline_sha256": baseline_digest,
        "configuration_setup_sha256": setup_digest,
        "production_writer_available": False,
        "transport_exposed_to_product": False,
        "write_authorized": False,
        "physical_router_targeted": False,
    }


def apply_rule(*, admin_url: str, prepare_payload: Mapping[str, Any]) -> dict[str, Any]:
    admin = base.LoopbackCHRAdmin(admin_url)
    admin.assert_disposable_chr()
    _assert_rule_absent(admin)
    plan = _render_plan(admin)
    expected_sha = str(prepare_payload.get("renderer", {}).get("plan_sha256") or "")
    if str(plan.get("plan_sha256") or "") != expected_sha:
        raise CHRPbrRouteSelectionError("production PBR renderer plan changed between prepare and apply")
    commands = plan.get("commands")
    if not isinstance(commands, list) or len(commands) != 1 or not isinstance(commands[0], Mapping):
        raise CHRPbrRouteSelectionError("production PBR renderer no longer emits exactly one command")
    result = _execute_script(
        admin,
        file_name=APPLY_FILE,
        script=str(commands[0].get("command") or "") + "\n",
    )
    runtime = _assert_rule_active(admin)
    admin.request("GET", "system/resource")
    return {
        "ok": True,
        "acceptance": "APPLIED",
        "plan_sha256": expected_sha,
        "import": result,
        "runtime": runtime,
        "management_rest_reachable_after_apply": True,
    }


def rollback_rule(*, admin_url: str, prepare_payload: Mapping[str, Any]) -> dict[str, Any]:
    admin = base.LoopbackCHRAdmin(admin_url)
    admin.assert_disposable_chr()
    _assert_rule_active(admin)
    result = _execute_script(admin, file_name=ROLLBACK_FILE, script=_rollback_rule_script())
    _assert_rule_absent(admin)
    setup_digest = base._canonical_digest(_configuration_snapshot(admin))
    expected_setup = str(prepare_payload.get("configuration_setup_sha256") or "")
    if setup_digest != expected_setup:
        raise CHRPbrRouteSelectionError("PBR rule rollback did not restore exact lab setup configuration")
    return {
        "ok": True,
        "acceptance": "ROLLED_BACK",
        "import": result,
        "configuration_setup_sha256": setup_digest,
        "rollback_to_setup_digest_restored": True,
    }


def finalize(
    *,
    admin_url: str,
    prepare_payload: Mapping[str, Any],
    baseline_flow: Mapping[str, Any],
    pbr_flow: Mapping[str, Any],
    rollback_flow: Mapping[str, Any],
) -> dict[str, Any]:
    admin = base.LoopbackCHRAdmin(admin_url)
    admin.assert_disposable_chr()
    _assert_rule_absent(admin)
    baseline_result = _assert_flow(baseline_flow, "MAIN")
    pbr_result = _assert_flow(pbr_flow, "PBR")
    rollback_result = _assert_flow(rollback_flow, "MAIN")
    _execute_script(admin, file_name=CLEANUP_FILE, script=_cleanup_script())
    _delete_temp_files(admin)
    final_digest = base._canonical_digest(_configuration_snapshot(admin))
    baseline_digest = str(prepare_payload.get("configuration_baseline_sha256") or "")
    if final_digest != baseline_digest:
        raise CHRPbrRouteSelectionError("PBR data-plane lab cleanup did not restore exact baseline configuration")
    base._assert_files_absent(admin, TEMP_FILES)
    return {
        "ok": True,
        "acceptance": "PASS",
        "scope": "disposable_chr_pbr_route_selection_data_plane",
        "workflow_sha": str(prepare_payload.get("workflow_sha") or ""),
        "platform": dict(prepare_payload.get("platform") or {}),
        "renderer": dict(prepare_payload.get("renderer") or {}),
        "packet_flow": {
            "baseline": baseline_result,
            "policy_applied": pbr_result,
            "policy_rolled_back": rollback_result,
            "observed_sequence": ["MAIN", "PBR", "MAIN"],
        },
        "route_selection_data_plane_acceptance": True,
        "rollback_to_setup_digest_restored": True,
        "lab_cleanup_digest_restored": True,
        "configuration_baseline_sha256": baseline_digest,
        "configuration_cleanup_sha256": final_digest,
        "temporary_files_removed": True,
        "production_writer_available": False,
        "transport_exposed_to_product": False,
        "write_authorized": False,
        "physical_router_targeted": False,
        "production_route_selection_claimed": False,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description="Prove production-rendered RouterOS PBR route selection on disposable CHR")
    sub = parser.add_subparsers(dest="command", required=True)

    p_prepare = sub.add_parser("prepare")
    p_prepare.add_argument("--admin-url", default="http://127.0.0.1:9980")
    p_prepare.add_argument("--workflow-sha", required=True)
    p_prepare.add_argument("--output", required=True)

    for name in ("apply", "rollback"):
        p = sub.add_parser(name)
        p.add_argument("--admin-url", default="http://127.0.0.1:9980")
        p.add_argument("--prepare", required=True)
        p.add_argument("--output", required=True)

    p_final = sub.add_parser("finalize")
    p_final.add_argument("--admin-url", default="http://127.0.0.1:9980")
    p_final.add_argument("--prepare", required=True)
    p_final.add_argument("--baseline-flow", required=True)
    p_final.add_argument("--pbr-flow", required=True)
    p_final.add_argument("--rollback-flow", required=True)
    p_final.add_argument("--output", required=True)

    args = parser.parse_args()
    output = Path(args.output)
    output.parent.mkdir(parents=True, exist_ok=True)
    try:
        if args.command == "prepare":
            result = prepare(admin_url=args.admin_url, workflow_sha=args.workflow_sha)
        elif args.command == "apply":
            result = apply_rule(admin_url=args.admin_url, prepare_payload=_load(args.prepare))
        elif args.command == "rollback":
            result = rollback_rule(admin_url=args.admin_url, prepare_payload=_load(args.prepare))
        else:
            result = finalize(
                admin_url=args.admin_url,
                prepare_payload=_load(args.prepare),
                baseline_flow=_load(args.baseline_flow),
                pbr_flow=_load(args.pbr_flow),
                rollback_flow=_load(args.rollback_flow),
            )
        rc = 0
    except (OSError, ValueError, base.CHRRenderDryRunError, mutation.CHRMutationRollbackError, CHRPbrRouteSelectionError) as exc:
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
        rc = 1
    output.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(json.dumps(result, indent=2, sort_keys=True))
    return rc


if __name__ == "__main__":
    raise SystemExit(main())
