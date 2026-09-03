from __future__ import annotations

import argparse
import json
import time
from pathlib import Path
from typing import Any, Mapping

import verify_pbr_baseline as baseline
from router_configuration.safe_subset_ir import IntentOperation, IntentRisk, SafeSubsetIR


class CHRPbrRouteSelectionError(RuntimeError):
    pass


TABLE_NAME = baseline.TABLE_NAME
RULE_NAME = baseline.RULE_NAME
RULE_COMMENT = baseline.RULE_COMMENT
SOURCE_CIDR = "198.51.100.0/24"
SERVICE_IP = "203.0.113.100"
SERVICE_CIDR = f"{SERVICE_IP}/32"
CORE_ADDRESS = "198.51.100.1/24"
WAN_ADDRESS = "192.0.2.2/30"
WAN_GATEWAY = "192.0.2.1"
CORE_COMMENT = "routercfg:lab:pbr-route-selection:core"
WAN_COMMENT = "routercfg:lab:pbr-route-selection:wan"
ROUTE_COMMENT = "routercfg:lab:pbr-route-selection:route"
APPLY_FILE = "routercfg-pbr-flow-apply.rsc"
ROLLBACK_FILE = "routercfg-pbr-flow-rollback.rsc"
TEMP_FILES = (APPLY_FILE, ROLLBACK_FILE, baseline.mutation.VERDICT_FILE)


def _load(path: str) -> dict[str, Any]:
    return json.loads(Path(path).read_text(encoding="utf-8"))


def _records(admin: baseline.base.LoopbackCHRAdmin, path: str) -> list[Mapping[str, Any]]:
    _, payload = admin.request("GET", path)
    return list(baseline.base._rows(payload))


def _normalized_rows(
    admin: baseline.base.LoopbackCHRAdmin,
    path: str,
    fields: tuple[str, ...],
) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for row in _records(admin, path):
        if baseline.base._is_true(row.get("dynamic")):
            continue
        rows.append({field: row[field] for field in fields if field in row})
    rows.sort(key=lambda item: json.dumps(item, sort_keys=True, ensure_ascii=False))
    return rows


def _configuration_snapshot(admin: baseline.base.LoopbackCHRAdmin) -> dict[str, Any]:
    return {
        "ip_addresses": _normalized_rows(
            admin,
            "ip/address",
            ("address", "network", "interface", "comment", "disabled"),
        ),
        "ip_routes": _normalized_rows(
            admin,
            "ip/route",
            (
                "dst-address",
                "gateway",
                "routing-table",
                "distance",
                "scope",
                "target-scope",
                "comment",
                "disabled",
            ),
        ),
        "routing_tables": _normalized_rows(
            admin,
            "routing/table",
            ("name", "fib", "disabled"),
        ),
        "routing_rules": _normalized_rows(
            admin,
            "routing/rule",
            ("src-address", "dst-address", "action", "table", "interface", "comment", "disabled"),
        ),
    }


def _digest(admin: baseline.base.LoopbackCHRAdmin) -> str:
    return baseline.base._canonical_digest(_configuration_snapshot(admin))


def _find_comment(
    admin: baseline.base.LoopbackCHRAdmin,
    path: str,
    comment: str,
) -> Mapping[str, Any] | None:
    return next(
        (row for row in _records(admin, path) if str(row.get("comment") or "") == comment),
        None,
    )


def _delete_comment(admin: baseline.base.LoopbackCHRAdmin, path: str, comment: str) -> None:
    for row in list(_records(admin, path)):
        if str(row.get("comment") or "") != comment:
            continue
        row_id = str(row.get(".id") or "").strip()
        if not row_id:
            raise CHRPbrRouteSelectionError(f"{path} object {comment!r} has no RouterOS id")
        admin.request("DELETE", f"{path}/{row_id}")
    if _find_comment(admin, path, comment) is not None:
        raise CHRPbrRouteSelectionError(f"failed to remove {path} object {comment!r}")


def _find_table(admin: baseline.base.LoopbackCHRAdmin) -> Mapping[str, Any] | None:
    return next(
        (row for row in _records(admin, "routing/table") if str(row.get("name") or "") == TABLE_NAME),
        None,
    )


def _remove_table(admin: baseline.base.LoopbackCHRAdmin) -> None:
    row = _find_table(admin)
    if row is None:
        return
    row_id = str(row.get(".id") or "").strip()
    if not row_id:
        raise CHRPbrRouteSelectionError("PBR lab routing table has no RouterOS id")
    admin.request("DELETE", f"routing/table/{row_id}")
    if _find_table(admin) is not None:
        raise CHRPbrRouteSelectionError("PBR lab routing table remains after cleanup")


def _owned_objects_absent(admin: baseline.base.LoopbackCHRAdmin) -> bool:
    return (
        _find_table(admin) is None
        and _find_comment(admin, "routing/rule", RULE_COMMENT) is None
        and _find_comment(admin, "ip/address", CORE_COMMENT) is None
        and _find_comment(admin, "ip/address", WAN_COMMENT) is None
        and _find_comment(admin, "ip/route", ROUTE_COMMENT) is None
    )


def _create_address(
    admin: baseline.base.LoopbackCHRAdmin,
    *,
    address: str,
    interface: str,
    comment: str,
) -> None:
    admin.request(
        "PUT",
        "ip/address",
        {"address": address, "interface": interface, "comment": comment, "disabled": False},
    )
    row = _find_comment(admin, "ip/address", comment)
    if row is None:
        raise CHRPbrRouteSelectionError(f"CHR did not expose address {comment!r}")
    if str(row.get("address") or "") != address or str(row.get("interface") or "") != interface:
        raise CHRPbrRouteSelectionError(f"CHR address {comment!r} does not match requested topology")


def _create_route(admin: baseline.base.LoopbackCHRAdmin) -> None:
    admin.request(
        "PUT",
        "ip/route",
        {
            "dst-address": SERVICE_CIDR,
            "gateway": WAN_GATEWAY,
            "routing-table": TABLE_NAME,
            "distance": 1,
            "comment": ROUTE_COMMENT,
            "disabled": False,
        },
    )
    deadline = time.monotonic() + 10.0
    while time.monotonic() < deadline:
        row = _find_comment(admin, "ip/route", ROUTE_COMMENT)
        if row is not None:
            gateway = str(row.get("gateway") or "")
            table = str(row.get("routing-table") or "")
            if (
                str(row.get("dst-address") or "") == SERVICE_CIDR
                and gateway.startswith(WAN_GATEWAY)
                and table == TABLE_NAME
                and not baseline.base._is_true(row.get("invalid"))
                and not baseline.base._is_true(row.get("inactive"))
                and not baseline.base._is_true(row.get("disabled"))
            ):
                return
        time.sleep(0.25)
    raise CHRPbrRouteSelectionError("custom-table service route did not become usable")


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


def _render_plan(admin: baseline.base.LoopbackCHRAdmin) -> dict[str, Any]:
    management_network = baseline._observed_management_network(admin)
    state, prerequisites = baseline._renderer_inputs(admin)
    plan = baseline.render_routeros_pbr(
        ir=_build_ir(management_network),
        state=state,
        prerequisites=prerequisites,
    ).as_dict()
    commands = plan.get("commands")
    if not isinstance(commands, list) or len(commands) != 1:
        raise CHRPbrRouteSelectionError("PBR route-selection gate requires exactly one renderer command")
    return plan


def _runtime_rule(admin: baseline.base.LoopbackCHRAdmin) -> dict[str, Any]:
    row = _find_comment(admin, "routing/rule", RULE_COMMENT)
    if row is None:
        raise CHRPbrRouteSelectionError("managed PBR routing rule is missing")
    if baseline.base._is_true(row.get("invalid")) or baseline.base._is_true(row.get("disabled")):
        raise CHRPbrRouteSelectionError("managed PBR routing rule is invalid or disabled")
    if (
        str(row.get("src-address") or "") != SOURCE_CIDR
        or str(row.get("dst-address") or "") != SERVICE_CIDR
        or str(row.get("action") or "") != "lookup-only-in-table"
        or str(row.get("table") or "") != TABLE_NAME
    ):
        raise CHRPbrRouteSelectionError("managed PBR routing rule does not match route-selection policy")
    admin.request("GET", "system/resource")
    return {
        "managed_rule_count": 1,
        "source_cidr_exact": True,
        "destination_cidr_exact": True,
        "lookup_only_in_table_exact": True,
        "table_reference_exact": True,
        "management_rest_reachable": True,
    }


def _assert_negative_flow(payload: Mapping[str, Any]) -> dict[str, Any]:
    requested = int(payload.get("requested_flows") or 0)
    successful = int(payload.get("successful_flows") or 0)
    failed = int(payload.get("failed_flows") or 0)
    tags = payload.get("tags")
    normalized = {str(k): int(v) for k, v in tags.items()} if isinstance(tags, Mapping) else {}
    if requested <= 0 or successful != 0 or failed != requested or normalized:
        raise CHRPbrRouteSelectionError(
            f"PBR negative control unexpectedly routed traffic: requested={requested} successful={successful} tags={normalized}"
        )
    return {
        "requested_flows": requested,
        "successful_flows": 0,
        "failed_flows": failed,
        "success_ratio": 0.0,
        "observed_tags": {},
        "blocked_without_policy": True,
    }


def _assert_positive_flow(payload: Mapping[str, Any]) -> dict[str, Any]:
    requested = int(payload.get("requested_flows") or 0)
    successful = int(payload.get("successful_flows") or 0)
    tags = payload.get("tags")
    normalized = {str(k): int(v) for k, v in tags.items()} if isinstance(tags, Mapping) else {}
    if requested <= 0 or successful != requested or normalized != {"PBR": requested}:
        raise CHRPbrRouteSelectionError(
            f"PBR selected-table flow failed: requested={requested} successful={successful} tags={normalized}"
        )
    return {
        "requested_flows": requested,
        "successful_flows": successful,
        "failed_flows": 0,
        "success_ratio": 1.0,
        "observed_tags": normalized,
    }


def prepare(*, admin_url: str, workflow_sha: str) -> dict[str, Any]:
    admin = baseline.base.LoopbackCHRAdmin(admin_url)
    platform = admin.assert_disposable_chr()
    interfaces = {str(row.get("name") or "") for row in _records(admin, "interface")}
    missing = sorted({"ether1", "ether2", "ether3"} - interfaces)
    if missing:
        raise CHRPbrRouteSelectionError(f"disposable CHR is missing PBR interfaces: {missing}")
    if not _owned_objects_absent(admin):
        raise CHRPbrRouteSelectionError("disposable CHR baseline already contains PBR route-selection lab objects")

    for name in TEMP_FILES:
        baseline.base._delete_file_if_present(admin, name)
    original_digest = _digest(admin)
    baseline._create_lab_table(admin)
    _create_address(admin, address=CORE_ADDRESS, interface="ether2", comment=CORE_COMMENT)
    _create_address(admin, address=WAN_ADDRESS, interface="ether3", comment=WAN_COMMENT)
    _create_route(admin)
    setup_digest = _digest(admin)
    if setup_digest == original_digest:
        raise CHRPbrRouteSelectionError("PBR lab setup did not change configuration digest")
    plan = _render_plan(admin)

    return {
        "ok": True,
        "acceptance": "PREPARED",
        "workflow_sha": workflow_sha,
        "platform": {
            "version": str(platform.get("version") or ""),
            "architecture": str(platform.get("architecture-name") or ""),
            "board_name": str(platform.get("board-name") or ""),
        },
        "fixture": {
            "source_cidr": SOURCE_CIDR,
            "service_cidr": SERVICE_CIDR,
            "table": TABLE_NAME,
            "core_interface": "ether2",
            "wan_interface": "ether3",
            "wan_gateway": WAN_GATEWAY,
        },
        "renderer": {
            "production_renderer_used": True,
            "plan_sha256": str(plan.get("plan_sha256") or ""),
            "command_count": int(plan.get("command_count") or 0),
            "mangle_routing_marks": bool(plan.get("mangle_routing_marks")),
        },
        "configuration_original_sha256": original_digest,
        "configuration_setup_sha256": setup_digest,
        "route_selection_data_plane_acceptance": False,
        "production_writer_available": False,
        "transport_exposed_to_product": False,
        "write_authorized": False,
        "physical_router_targeted": False,
    }


def apply(*, admin_url: str, prepared: Mapping[str, Any]) -> dict[str, Any]:
    admin = baseline.base.LoopbackCHRAdmin(admin_url)
    admin.assert_disposable_chr()
    plan = _render_plan(admin)
    expected_plan_sha = str((prepared.get("renderer") or {}).get("plan_sha256") or "")
    if str(plan.get("plan_sha256") or "") != expected_plan_sha:
        raise CHRPbrRouteSelectionError("PBR renderer plan changed between setup and apply")
    commands = plan["commands"]
    apply_script = str(commands[0]["command"]) + "\n"
    baseline.chunked._create_text_file_chunk_verified(admin, APPLY_FILE, apply_script)
    apply_result = baseline.mutation._execute_import(admin, file_name=APPLY_FILE, expect_success=True)
    runtime = _runtime_rule(admin)
    mutated_digest = _digest(admin)
    setup_digest = str(prepared.get("configuration_setup_sha256") or "")
    if mutated_digest == setup_digest:
        raise CHRPbrRouteSelectionError("PBR rule apply did not change configuration digest")
    baseline.base._delete_file_if_present(admin, APPLY_FILE)
    baseline.base._delete_file_if_present(admin, baseline.mutation.VERDICT_FILE)
    return {
        "ok": True,
        "acceptance": "APPLIED",
        "workflow_sha": str(prepared.get("workflow_sha") or ""),
        "renderer": dict(prepared.get("renderer") or {}),
        "runtime": runtime,
        "apply": {"verdict": str(apply_result.get("verdict") or "")},
        "configuration_setup_sha256": setup_digest,
        "configuration_mutated_sha256": mutated_digest,
        "route_selection_data_plane_acceptance": False,
        "production_writer_available": False,
        "transport_exposed_to_product": False,
        "write_authorized": False,
        "physical_router_targeted": False,
    }


def finalize(
    *,
    admin_url: str,
    prepared: Mapping[str, Any],
    applied: Mapping[str, Any],
    negative_flow: Mapping[str, Any],
    positive_flow: Mapping[str, Any],
) -> dict[str, Any]:
    admin = baseline.base.LoopbackCHRAdmin(admin_url)
    admin.assert_disposable_chr()
    negative = _assert_negative_flow(negative_flow)
    positive = _assert_positive_flow(positive_flow)
    _runtime_rule(admin)

    rollback_script = f'/routing/rule/remove [find where comment="{RULE_COMMENT}"]\n'
    baseline.chunked._create_text_file_chunk_verified(admin, ROLLBACK_FILE, rollback_script)
    rollback_result = baseline.mutation._execute_import(admin, file_name=ROLLBACK_FILE, expect_success=True)
    if _find_comment(admin, "routing/rule", RULE_COMMENT) is not None:
        raise CHRPbrRouteSelectionError("managed PBR rule remains after rollback")
    setup_digest = str(prepared.get("configuration_setup_sha256") or "")
    rule_rollback_digest = _digest(admin)
    if rule_rollback_digest != setup_digest:
        raise CHRPbrRouteSelectionError("PBR rule rollback did not restore exact setup digest")

    _delete_comment(admin, "ip/route", ROUTE_COMMENT)
    _delete_comment(admin, "ip/address", CORE_COMMENT)
    _delete_comment(admin, "ip/address", WAN_COMMENT)
    _remove_table(admin)
    cleanup_digest = _digest(admin)
    original_digest = str(prepared.get("configuration_original_sha256") or "")
    if cleanup_digest != original_digest:
        raise CHRPbrRouteSelectionError("PBR lab cleanup did not restore original baseline digest")
    for name in TEMP_FILES:
        baseline.base._delete_file_if_present(admin, name)
    baseline.base._assert_files_absent(admin, TEMP_FILES)

    return {
        "ok": True,
        "acceptance": "PASS",
        "scope": "disposable_chr_pbr_route_selection_data_plane",
        "workflow_sha": str(prepared.get("workflow_sha") or ""),
        "platform": dict(prepared.get("platform") or {}),
        "renderer": dict(prepared.get("renderer") or {}),
        "packet_flow": {
            "without_pbr_negative_control": negative,
            "with_pbr_selected_table": positive,
        },
        "route_selection_data_plane_acceptance": True,
        "negative_control_acceptance": True,
        "rollback": {"verdict": str(rollback_result.get("verdict") or "")},
        "configuration_original_sha256": original_digest,
        "configuration_setup_sha256": setup_digest,
        "configuration_mutated_sha256": str(applied.get("configuration_mutated_sha256") or ""),
        "configuration_rule_rollback_sha256": rule_rollback_digest,
        "configuration_cleanup_sha256": cleanup_digest,
        "rule_rollback_digest_restored": True,
        "lab_setup_cleanup_restored": True,
        "temporary_files_removed": True,
        "management_rest_reachable_after_flow": True,
        "production_writer_available": False,
        "transport_exposed_to_product": False,
        "write_authorized": False,
        "physical_router_targeted": False,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description="Prove RouterOS PBR route-selection packet flow on disposable CHR")
    sub = parser.add_subparsers(dest="command", required=True)

    p_prepare = sub.add_parser("prepare")
    p_prepare.add_argument("--admin-url", default="http://127.0.0.1:10280")
    p_prepare.add_argument("--workflow-sha", required=True)
    p_prepare.add_argument("--output", required=True)

    p_apply = sub.add_parser("apply")
    p_apply.add_argument("--admin-url", default="http://127.0.0.1:10280")
    p_apply.add_argument("--prepared", required=True)
    p_apply.add_argument("--output", required=True)

    p_final = sub.add_parser("finalize")
    p_final.add_argument("--admin-url", default="http://127.0.0.1:10280")
    p_final.add_argument("--prepared", required=True)
    p_final.add_argument("--applied", required=True)
    p_final.add_argument("--negative-flow", required=True)
    p_final.add_argument("--positive-flow", required=True)
    p_final.add_argument("--output", required=True)

    args = parser.parse_args()
    output = Path(args.output)
    output.parent.mkdir(parents=True, exist_ok=True)
    try:
        if args.command == "prepare":
            result = prepare(admin_url=args.admin_url, workflow_sha=args.workflow_sha)
        elif args.command == "apply":
            result = apply(admin_url=args.admin_url, prepared=_load(args.prepared))
        else:
            result = finalize(
                admin_url=args.admin_url,
                prepared=_load(args.prepared),
                applied=_load(args.applied),
                negative_flow=_load(args.negative_flow),
                positive_flow=_load(args.positive_flow),
            )
        rc = 0
    except (
        OSError,
        ValueError,
        KeyError,
        baseline.base.CHRRenderDryRunError,
        baseline.mutation.CHRMutationRollbackError,
        baseline.CHRPbrBaselineError,
        CHRPbrRouteSelectionError,
    ) as exc:
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
