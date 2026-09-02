from __future__ import annotations

import argparse
import ipaddress
import json
from pathlib import Path
from typing import Any, Mapping

import verify_mutation_rollback as mutation
import verify_render_dry_run as base
import verify_render_dry_run_chunked as chunked
from router_configuration.routeros_firewall_renderer import (
    ADDRESS_COMMENT_PREFIX,
    CHAIN_COMMENT_PREFIX,
    CORE_INTERFACE_LIST,
    ICMP_CHAIN,
    ICMP_COMMENT_PREFIX,
    INPUT_CHAIN,
    INPUT_JUMP_COMMENT,
    MANAGEMENT_ADDRESS_LIST,
    STAGING_GUARD_COMMENT,
    WAN_INTERFACE_LIST,
    render_routeros_firewall,
)
from router_configuration.routeros_renderer import RouterOSSafeSubsetRenderer
from router_configuration.safe_subset_ir import IntentOperation, IntentRisk, SafeSubsetIR


class CHRFirewallBaselineError(RuntimeError):
    pass


APPLY_FILE = "routercfg-firewall-apply.rsc"
ROLLBACK_FILE = "routercfg-firewall-rollback.rsc"
VERDICT_FILE = "routercfg-firewall-verdict.txt"
TEMP_FILES = (APPLY_FILE, ROLLBACK_FILE, VERDICT_FILE, mutation.VERDICT_FILE)
SYNTHETIC_SERVICE_SOURCE = "198.51.100.10/32"
SYNTHETIC_SERVICE_PORT = 9443


def _observed_management_network(admin: base.LoopbackCHRAdmin) -> tuple[str, str]:
    """Derive the lab management CIDR from live ether1 state instead of guessing it."""

    _, payload = admin.request("GET", "ip/address")
    candidates: list[tuple[int, str, str]] = []
    for row in base._rows(payload):
        if str(row.get("interface") or "") != "ether1":
            continue
        address = str(row.get("address") or "").strip()
        try:
            interface = ipaddress.ip_interface(address)
        except ValueError:
            continue
        if interface.version != 4 or interface.ip.is_loopback or interface.ip.is_unspecified:
            continue
        if interface.network.prefixlen == 0 or interface.network.prefixlen >= 31:
            continue
        candidates.append((interface.network.prefixlen, str(interface), str(interface.network)))
    if not candidates:
        raise CHRFirewallBaselineError(
            "disposable CHR ether1 has no usable bounded IPv4 management network"
        )
    candidates.sort(key=lambda item: (-item[0], item[1]))
    _, observed_address, observed_network = candidates[0]
    return observed_address, observed_network


def _build_ir(management_network: str) -> dict[str, Any]:
    """Build a lab-only fixture from one observed fact plus RFC 5737 test data."""

    return SafeSubsetIR(
        device_id="chr-firewall-baseline-lab",
        operations=(
            IntentOperation(
                operation_id="topology.wan.lab-wan",
                feature="topology",
                resource="wan_role",
                attributes={
                    "name": "lab-wan",
                    "interface": "ether2",
                    "capacity_mbps": 1000,
                },
                risk=IntentRisk.MEDIUM,
                requires=("interfaces",),
            ),
            IntentOperation(
                operation_id="topology.core",
                feature="topology",
                resource="core_uplink_role",
                attributes={"interface": "ether1", "capacity_mbps": 1000},
                risk=IntentRisk.MEDIUM,
                requires=("interfaces",),
            ),
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
                    "required_wan_services": [
                        {
                            "name": "synthetic-runtime-service",
                            "protocol": "tcp",
                            "dst_port": SYNTHETIC_SERVICE_PORT,
                            "source_cidrs": [SYNTHETIC_SERVICE_SOURCE],
                        }
                    ],
                },
                risk=IntentRisk.HIGH,
                requires=("firewall", "nat", "management_path"),
            ),
        ),
    ).as_dict()


def _render_fixture(management_network: str) -> dict[str, Any]:
    ir = _build_ir(management_network)
    base_plan = RouterOSSafeSubsetRenderer().render(ir).as_dict()
    blockers = base_plan.get("blocked_operations", [])
    if not isinstance(blockers, list):
        raise CHRFirewallBaselineError("base renderer blockers must be a list")
    blocker_ids = {
        str(item.get("operation_id") or "")
        for item in blockers
        if isinstance(item, Mapping)
    }
    if blocker_ids != {"security.baseline"}:
        raise CHRFirewallBaselineError(
            f"firewall fixture expected only security.baseline blocker, observed {sorted(blocker_ids)}"
        )

    firewall_plan = render_routeros_firewall(ir=ir).as_dict()
    base_commands = base_plan.get("commands", [])
    firewall_commands = firewall_plan.get("commands", [])
    if not isinstance(base_commands, list) or not isinstance(firewall_commands, list):
        raise CHRFirewallBaselineError("renderer command collections must be lists")
    if len(base_commands) != 4 or len(firewall_commands) != 23:
        raise CHRFirewallBaselineError(
            "firewall CHR fixture requires 4 topology + 23 firewall commands; "
            f"observed {len(base_commands)} + {len(firewall_commands)}"
        )
    commands = [*base_commands, *firewall_commands]
    return {
        "schema_version": "chr-firewall-render-fixture/1",
        "ir": ir,
        "base_command_count": len(base_commands),
        "firewall_command_count": len(firewall_commands),
        "command_count": len(commands),
        "commands": commands,
        "firewall_plan": firewall_plan,
        "production_writer_available": False,
        "write_authorized": False,
    }


def _normalized_rows(
    admin: base.LoopbackCHRAdmin,
    path: str,
    fields: tuple[str, ...],
) -> list[dict[str, Any]]:
    _, payload = admin.request("GET", path)
    normalized: list[dict[str, Any]] = []
    for row in base._rows(payload):
        if base._is_true(row.get("dynamic")):
            continue
        normalized.append({field: row[field] for field in fields if field in row})
    normalized.sort(key=lambda item: json.dumps(item, sort_keys=True, ensure_ascii=False))
    return normalized


def _configuration_snapshot(admin: base.LoopbackCHRAdmin) -> dict[str, Any]:
    snapshot = base._configuration_snapshot(admin)
    snapshot["firewall_filter"] = _normalized_rows(
        admin,
        "ip/firewall/filter",
        (
            "chain",
            "action",
            "connection-state",
            "protocol",
            "icmp-options",
            "in-interface-list",
            "src-address-list",
            "dst-port",
            "jump-target",
            "comment",
            "disabled",
        ),
    )
    snapshot["firewall_address_list"] = _normalized_rows(
        admin,
        "ip/firewall/address-list",
        ("list", "address", "comment", "disabled"),
    )
    return snapshot


def _owned_objects_absent(admin: base.LoopbackCHRAdmin) -> bool:
    _, filter_payload = admin.request("GET", "ip/firewall/filter")
    for row in base._rows(filter_payload):
        comment = str(row.get("comment") or "")
        chain = str(row.get("chain") or "")
        if (
            comment == INPUT_JUMP_COMMENT
            or comment == STAGING_GUARD_COMMENT
            or comment.startswith(CHAIN_COMMENT_PREFIX)
            or comment.startswith(ICMP_COMMENT_PREFIX)
            or chain in {INPUT_CHAIN, ICMP_CHAIN}
        ):
            return False

    _, address_payload = admin.request("GET", "ip/firewall/address-list")
    if any(
        str(row.get("comment") or "").startswith(ADDRESS_COMMENT_PREFIX)
        for row in base._rows(address_payload)
    ):
        return False

    _, list_payload = admin.request("GET", "interface/list")
    if any(
        str(row.get("name") or "") in {WAN_INTERFACE_LIST, CORE_INTERFACE_LIST}
        for row in base._rows(list_payload)
    ):
        return False
    return True


def _rollback_script() -> str:
    commands = (
        f'/ip/firewall/filter/remove [find where comment="{INPUT_JUMP_COMMENT}"]',
        f'/ip/firewall/filter/remove [find where comment="{STAGING_GUARD_COMMENT}"]',
        f'/ip/firewall/filter/remove [find where chain="{INPUT_CHAIN}"]',
        f'/ip/firewall/filter/remove [find where chain="{ICMP_CHAIN}"]',
        f'/ip/firewall/address-list/remove [find where comment~"^{ADDRESS_COMMENT_PREFIX}"]',
        '/interface/list/member/remove [find where comment~"^routercfg:managed:wan:"]',
        '/interface/list/member/remove [find where comment="routercfg:managed:core-uplink"]',
        f'/interface/list/remove [find where name="{WAN_INTERFACE_LIST}"]',
        f'/interface/list/remove [find where name="{CORE_INTERFACE_LIST}"]',
    )
    return "\n".join(commands) + "\n"


def _runtime_state(admin: base.LoopbackCHRAdmin) -> dict[str, Any]:
    _, filter_payload = admin.request("GET", "ip/firewall/filter")
    filter_rows = list(base._rows(filter_payload))
    managed_rows = []
    for row in filter_rows:
        comment = str(row.get("comment") or "")
        chain = str(row.get("chain") or "")
        if (
            comment == INPUT_JUMP_COMMENT
            or comment.startswith(CHAIN_COMMENT_PREFIX)
            or comment.startswith(ICMP_COMMENT_PREFIX)
            or chain in {INPUT_CHAIN, ICMP_CHAIN}
        ):
            managed_rows.append(row)

    invalid = [
        str(row.get("comment") or row.get(".id") or "")
        for row in managed_rows
        if base._is_true(row.get("invalid"))
    ]
    disabled = [
        str(row.get("comment") or row.get(".id") or "")
        for row in managed_rows
        if base._is_true(row.get("disabled"))
    ]
    if invalid:
        raise CHRFirewallBaselineError(f"managed firewall rules invalid at runtime: {invalid}")
    if disabled:
        raise CHRFirewallBaselineError(f"managed firewall rules unexpectedly disabled: {disabled}")
    if any(str(row.get("comment") or "") == STAGING_GUARD_COMMENT for row in filter_rows):
        raise CHRFirewallBaselineError("firewall staging guard remained after activation")

    expected_input_comments = [
        CHAIN_COMMENT_PREFIX + "010-established-related",
        CHAIN_COMMENT_PREFIX + "020-invalid-drop",
        CHAIN_COMMENT_PREFIX + "030-management-antispoof",
        CHAIN_COMMENT_PREFIX + "040-essential-icmp",
        CHAIN_COMMENT_PREFIX + "050-management-accept",
        CHAIN_COMMENT_PREFIX + "060-wan-service:001",
        CHAIN_COMMENT_PREFIX + "090-wan-default-deny",
        CHAIN_COMMENT_PREFIX + "099-input-default-deny",
    ]
    input_rows = [row for row in filter_rows if str(row.get("chain") or "") == INPUT_CHAIN]
    input_comments = [str(row.get("comment") or "") for row in input_rows]
    if input_comments != expected_input_comments:
        raise CHRFirewallBaselineError(
            f"managed input-chain order mismatch: expected={expected_input_comments} observed={input_comments}"
        )

    expected_icmp_comments = [
        ICMP_COMMENT_PREFIX + "010-echo-reply",
        ICMP_COMMENT_PREFIX + "020-network-unreachable",
        ICMP_COMMENT_PREFIX + "030-host-unreachable",
        ICMP_COMMENT_PREFIX + "040-fragmentation-required",
        ICMP_COMMENT_PREFIX + "050-echo-request",
        ICMP_COMMENT_PREFIX + "060-time-exceeded",
        ICMP_COMMENT_PREFIX + "070-parameter-problem",
        ICMP_COMMENT_PREFIX + "099-drop-other",
    ]
    icmp_rows = [row for row in filter_rows if str(row.get("chain") or "") == ICMP_CHAIN]
    icmp_comments = [str(row.get("comment") or "") for row in icmp_rows]
    if icmp_comments != expected_icmp_comments:
        raise CHRFirewallBaselineError(
            f"managed ICMP-chain order mismatch: expected={expected_icmp_comments} observed={icmp_comments}"
        )

    jump_rows = [row for row in filter_rows if str(row.get("comment") or "") == INPUT_JUMP_COMMENT]
    if len(jump_rows) != 1:
        raise CHRFirewallBaselineError(f"expected one managed input jump, observed {len(jump_rows)}")
    jump = jump_rows[0]
    if (
        str(jump.get("chain") or "") != "input"
        or str(jump.get("action") or "") != "jump"
        or str(jump.get("jump-target") or "") != INPUT_CHAIN
    ):
        raise CHRFirewallBaselineError("managed input jump runtime fields do not match the renderer")
    static_input = [
        row
        for row in filter_rows
        if str(row.get("chain") or "") == "input" and not base._is_true(row.get("dynamic"))
    ]
    if not static_input or str(static_input[0].get("comment") or "") != INPUT_JUMP_COMMENT:
        raise CHRFirewallBaselineError("managed input jump is not the first static input rule")

    by_comment = {str(row.get("comment") or ""): row for row in input_rows}
    anti_spoof = by_comment[CHAIN_COMMENT_PREFIX + "030-management-antispoof"]
    management = by_comment[CHAIN_COMMENT_PREFIX + "050-management-accept"]
    wan_deny = by_comment[CHAIN_COMMENT_PREFIX + "090-wan-default-deny"]
    service = by_comment[CHAIN_COMMENT_PREFIX + "060-wan-service:001"]
    if (
        str(anti_spoof.get("action") or "") != "drop"
        or str(anti_spoof.get("in-interface-list") or "") != WAN_INTERFACE_LIST
        or str(anti_spoof.get("src-address-list") or "") != MANAGEMENT_ADDRESS_LIST
    ):
        raise CHRFirewallBaselineError("management-source anti-spoof rule fields are invalid")
    if (
        str(management.get("action") or "") != "accept"
        or str(management.get("in-interface-list") or "") != CORE_INTERFACE_LIST
        or str(management.get("src-address-list") or "") != MANAGEMENT_ADDRESS_LIST
    ):
        raise CHRFirewallBaselineError("management accept is not bounded to core plus management sources")
    if (
        str(wan_deny.get("action") or "") != "drop"
        or str(wan_deny.get("in-interface-list") or "") != WAN_INTERFACE_LIST
    ):
        raise CHRFirewallBaselineError("WAN input default-deny rule fields are invalid")
    if (
        str(service.get("action") or "") != "accept"
        or str(service.get("in-interface-list") or "") != WAN_INTERFACE_LIST
        or str(service.get("protocol") or "") != "tcp"
        or str(service.get("dst-port") or "") != str(SYNTHETIC_SERVICE_PORT)
    ):
        raise CHRFirewallBaselineError("explicit WAN service exception fields are invalid")

    _, address_payload = admin.request("GET", "ip/firewall/address-list")
    managed_addresses = [
        row
        for row in base._rows(address_payload)
        if str(row.get("comment") or "").startswith(ADDRESS_COMMENT_PREFIX)
    ]
    if len(managed_addresses) != 2:
        raise CHRFirewallBaselineError(
            f"expected two managed firewall address-list rows, observed {len(managed_addresses)}"
        )

    _, member_payload = admin.request("GET", "interface/list/member")
    managed_members = [
        row
        for row in base._rows(member_payload)
        if str(row.get("comment") or "").startswith("routercfg:managed:")
    ]
    member_pairs = {
        (str(row.get("list") or ""), str(row.get("interface") or ""))
        for row in managed_members
    }
    expected_pairs = {(WAN_INTERFACE_LIST, "ether2"), (CORE_INTERFACE_LIST, "ether1")}
    if member_pairs != expected_pairs:
        raise CHRFirewallBaselineError(
            f"firewall interface-list membership mismatch: expected={expected_pairs} observed={member_pairs}"
        )

    # A fresh REST read proves the active policy did not cut the observed
    # management path after the import completed.
    _, resource = admin.request("GET", "system/resource")
    if not isinstance(resource, Mapping):
        raise CHRFirewallBaselineError("management REST path did not survive firewall activation")

    return {
        "managed_filter_count": len(managed_rows),
        "managed_filter_invalid_count": 0,
        "managed_filter_disabled_count": 0,
        "managed_address_count": len(managed_addresses),
        "input_chain_order": input_comments,
        "icmp_chain_order": icmp_comments,
        "input_jump_first": True,
        "management_path_alive": True,
        "management_accept_core_only": True,
        "wan_input_default_deny": True,
        "management_source_antispoof_before_icmp": True,
        "explicit_wan_service_bounded": True,
    }


def verify_firewall_baseline(*, admin_url: str) -> dict[str, Any]:
    admin = base.LoopbackCHRAdmin(admin_url)
    platform = admin.assert_disposable_chr()
    observed_address, management_network = _observed_management_network(admin)
    if not _owned_objects_absent(admin):
        raise CHRFirewallBaselineError("fresh CHR already contains routercfg-owned firewall objects")

    fixture = _render_fixture(management_network)
    commands = fixture["commands"]
    apply_script = "\n".join(str(item["command"]) for item in commands) + "\n"
    rollback_script = _rollback_script()

    for name in TEMP_FILES:
        base._delete_file_if_present(admin, name)

    baseline = _configuration_snapshot(admin)
    baseline_digest = base._canonical_digest(baseline)
    dry_run_digest = None
    mutated_digest = None
    rollback_digest = None
    apply_result: dict[str, Any] | None = None
    runtime: dict[str, Any] | None = None
    rollback_result: dict[str, Any] | None = None
    applied = False
    rollback_completed = False

    try:
        chunked._create_text_file_chunk_verified(admin, APPLY_FILE, apply_script)
        chunked._create_text_file_chunk_verified(admin, ROLLBACK_FILE, rollback_script)

        chunked._create_text_file_chunk_verified(admin, VERDICT_FILE, "PENDING")
        rollback_dry_run = base._execute_import_dry_run(
            admin,
            file_name=ROLLBACK_FILE,
            verdict_name=VERDICT_FILE,
            expect_success=True,
        )
        chunked._create_text_file_chunk_verified(admin, VERDICT_FILE, "PENDING")
        apply_dry_run = base._execute_import_dry_run(
            admin,
            file_name=APPLY_FILE,
            verdict_name=VERDICT_FILE,
            expect_success=True,
        )
        dry_run_digest = base._canonical_digest(_configuration_snapshot(admin))
        if dry_run_digest != baseline_digest:
            raise CHRFirewallBaselineError("RouterOS configuration changed during firewall dry-run gate")

        apply_result = mutation._execute_import(admin, file_name=APPLY_FILE, expect_success=True)
        applied = True
        mutated_digest = base._canonical_digest(_configuration_snapshot(admin))
        if mutated_digest == baseline_digest:
            raise CHRFirewallBaselineError("firewall apply did not change the RouterOS configuration digest")
        runtime = _runtime_state(admin)

        rollback_result = mutation._execute_import(admin, file_name=ROLLBACK_FILE, expect_success=True)
        rollback_completed = True
        if not _owned_objects_absent(admin):
            raise CHRFirewallBaselineError("routercfg-owned firewall objects remain after rollback")
        rollback_digest = base._canonical_digest(_configuration_snapshot(admin))
        if rollback_digest != baseline_digest:
            raise CHRFirewallBaselineError(
                "firewall rollback completed but configuration digest did not return to baseline"
            )
    finally:
        if applied and not rollback_completed:
            try:
                mutation._execute_import(admin, file_name=ROLLBACK_FILE, expect_success=True)
            except (base.CHRRenderDryRunError, mutation.CHRMutationRollbackError, OSError):
                pass
        for name in TEMP_FILES:
            try:
                base._delete_file_if_present(admin, name)
            except (base.CHRRenderDryRunError, OSError):
                pass

    return {
        "schema_version": "chr-firewall-baseline-evidence/1",
        "ok": True,
        "acceptance": "PASS",
        "scope": "disposable_chr_firewall_dryrun_runtime_rollback",
        "platform": {
            "version": str(platform.get("version") or ""),
            "architecture": str(platform.get("architecture-name") or ""),
            "board_name": str(platform.get("board-name") or ""),
        },
        "management_observation": {
            "interface": "ether1",
            "observed_address": observed_address,
            "observed_network": management_network,
            "source": "live_chr_ip_address_state",
            "invented": False,
        },
        "fixture": {
            "kind": "lab_only_observed_management_plus_rfc5737_service_source",
            "base_command_count": fixture["base_command_count"],
            "firewall_command_count": fixture["firewall_command_count"],
            "command_count": fixture["command_count"],
            "synthetic_service_source": SYNTHETIC_SERVICE_SOURCE,
            "synthetic_service_port": SYNTHETIC_SERVICE_PORT,
        },
        "dry_run": {
            "rollback": rollback_dry_run,
            "apply": apply_dry_run,
            "configuration_unchanged": dry_run_digest == baseline_digest,
        },
        "apply": apply_result,
        "runtime": runtime,
        "rollback": rollback_result,
        "configuration_baseline_sha256": baseline_digest,
        "configuration_mutated_sha256": mutated_digest,
        "configuration_rollback_sha256": rollback_digest,
        "mutation_observed": mutated_digest is not None and mutated_digest != baseline_digest,
        "rollback_digest_restored": rollback_digest == baseline_digest,
        "temporary_files_removed": True,
        "production_writer_available": False,
        "transport_exposed_to_product": False,
        "write_authorized": False,
        "physical_router_targeted": False,
    }


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Validate enterprise RouterOS firewall generation on disposable CHR"
    )
    parser.add_argument("--admin-url", default="http://127.0.0.1:9480")
    parser.add_argument("--output", required=True)
    args = parser.parse_args()

    output = Path(args.output)
    output.parent.mkdir(parents=True, exist_ok=True)
    try:
        result = verify_firewall_baseline(admin_url=args.admin_url)
        rc = 0
    except (
        OSError,
        ValueError,
        base.CHRRenderDryRunError,
        mutation.CHRMutationRollbackError,
        CHRFirewallBaselineError,
    ) as exc:
        result = {
            "schema_version": "chr-firewall-baseline-evidence/1",
            "ok": False,
            "acceptance": "FAIL",
            "error": str(exc),
            "production_writer_available": False,
            "transport_exposed_to_product": False,
            "write_authorized": False,
            "physical_router_targeted": False,
        }
        rc = 18

    output.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(json.dumps(result, indent=2, sort_keys=True))
    return rc


if __name__ == "__main__":
    raise SystemExit(main())
