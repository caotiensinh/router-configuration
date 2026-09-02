from __future__ import annotations

import argparse
import ipaddress
import json
from pathlib import Path
from typing import Any, Mapping

import verify_mutation_rollback as mutation
import verify_render_dry_run as base
import verify_render_dry_run_chunked as chunked
from router_configuration.routeros_vlan_renderer import render_routeros_vlan
from router_configuration.safe_subset_ir import IntentOperation, IntentRisk, SafeSubsetIR


class CHRVlanBaselineError(RuntimeError):
    pass


APPLY_FILE = "routercfg-vlan-apply.rsc"
ROLLBACK_FILE = "routercfg-vlan-rollback.rsc"
VERDICT_FILE = "routercfg-vlan-verdict.txt"
TEMP_FILES = (APPLY_FILE, ROLLBACK_FILE, VERDICT_FILE, mutation.VERDICT_FILE)
BRIDGE = "routercfg-bridge-lab"
MGMT_INTERFACE = "routercfg-mgmt-vlan10"
MGMT_ADDRESS = "192.0.2.1/24"
MGMT_VLAN = 10
USER_VLAN = 20
TRUNK_PORT = "ether2"
ACCESS_PORT = "ether3"
OOB_MANAGEMENT = "ether1"
COMMENT_PREFIX = "routercfg:managed:vlan:"


def _records(admin: base.LoopbackCHRAdmin, path: str) -> list[Mapping[str, Any]]:
    _, payload = admin.request("GET", path)
    return list(base._rows(payload))


def _live_state(admin: base.LoopbackCHRAdmin) -> dict[str, Any]:
    return {
        "interfaces": [dict(row) for row in _records(admin, "interface")],
        "ip_addresses": [dict(row) for row in _records(admin, "ip/address")],
    }


def _live_prerequisites(admin: base.LoopbackCHRAdmin) -> dict[str, Any]:
    return {
        "schema_version": "routeros-render-prerequisites/1",
        "switching": {
            "bridges": [dict(row) for row in _records(admin, "interface/bridge")],
            "bridge_ports": [dict(row) for row in _records(admin, "interface/bridge/port")],
            "bridge_vlans": [dict(row) for row in _records(admin, "interface/bridge/vlan")],
            "vlan_interfaces": [dict(row) for row in _records(admin, "interface/vlan")],
        },
    }


def _assert_synthetic_management_network_is_free(state: Mapping[str, Any]) -> None:
    target = ipaddress.ip_interface(MGMT_ADDRESS).network
    rows = state.get("ip_addresses", [])
    if not isinstance(rows, list):
        raise CHRVlanBaselineError("live IP address state is not a list")
    for row in rows:
        if not isinstance(row, Mapping):
            continue
        raw = str(row.get("address") or "").strip()
        if not raw:
            continue
        try:
            existing = ipaddress.ip_interface(raw)
        except ValueError:
            continue
        if existing.version == 4 and target.overlaps(existing.network):
            raise CHRVlanBaselineError(
                f"RFC5737 management fixture {MGMT_ADDRESS} overlaps live CHR address {raw}"
            )


def _build_ir() -> dict[str, Any]:
    return SafeSubsetIR(
        device_id="chr-vlan-baseline-lab",
        operations=(
            IntentOperation(
                operation_id="segmentation.vlan",
                feature="segmentation",
                resource="vlan_segmentation_policy",
                attributes={
                    "bridge": BRIDGE,
                    "vlan_filtering": True,
                    "activation_order": "management_first_vlan_filtering_last",
                    "vlans": [
                        {"id": MGMT_VLAN, "name": "management"},
                        {"id": USER_VLAN, "name": "users"},
                    ],
                    "ports": [
                        {
                            "interface": TRUNK_PORT,
                            "mode": "trunk",
                            "allowed_vlans": [MGMT_VLAN, USER_VLAN],
                            "frame_types": "admit-only-vlan-tagged",
                        },
                        {
                            "interface": ACCESS_PORT,
                            "mode": "access",
                            "access_vlan": USER_VLAN,
                            "frame_types": "admit-only-untagged-and-priority-tagged",
                        },
                    ],
                    "management": {
                        "vlan_id": MGMT_VLAN,
                        "address": MGMT_ADDRESS,
                    },
                },
                risk=IntentRisk.HIGH,
                requires=("bridge", "vlan", "management_path"),
            ),
        ),
    ).as_dict()


def _management_path() -> dict[str, Any]:
    return {
        "ok": True,
        "interface": OOB_MANAGEMENT,
        "evidence_ref": "live_chr_loopback_rest_via_ether1",
    }


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
        "bridges": _normalized_rows(
            admin,
            "interface/bridge",
            ("name", "vlan-filtering", "protocol-mode", "comment", "disabled"),
        ),
        "bridge_ports": _normalized_rows(
            admin,
            "interface/bridge/port",
            (
                "bridge",
                "interface",
                "frame-types",
                "ingress-filtering",
                "pvid",
                "comment",
                "disabled",
            ),
        ),
        "bridge_vlans": _normalized_rows(
            admin,
            "interface/bridge/vlan",
            ("bridge", "vlan-ids", "tagged", "untagged", "comment", "disabled"),
        ),
        "vlan_interfaces": _normalized_rows(
            admin,
            "interface/vlan",
            ("name", "interface", "vlan-id", "comment", "disabled"),
        ),
        "ip_addresses": _normalized_rows(
            admin,
            "ip/address",
            ("address", "interface", "comment", "disabled"),
        ),
    }


def _owned_objects_absent(admin: base.LoopbackCHRAdmin) -> bool:
    checks = (
        ("interface/bridge", "comment"),
        ("interface/bridge/port", "comment"),
        ("interface/bridge/vlan", "comment"),
        ("interface/vlan", "comment"),
        ("ip/address", "comment"),
    )
    for path, field in checks:
        if any(
            str(row.get(field) or "").startswith(COMMENT_PREFIX)
            for row in _records(admin, path)
        ):
            return False
    return True


def _rollback_script() -> str:
    """Remove only routercfg-owned VLAN objects in reverse dependency order."""

    return "\n".join(
        (
            f'/ip/address/remove [find where comment="{COMMENT_PREFIX}management-address"]',
            f'/interface/vlan/remove [find where comment="{COMMENT_PREFIX}management-interface"]',
            f'/interface/bridge/vlan/remove [find where comment~"^{COMMENT_PREFIX}membership:"]',
            f'/interface/bridge/port/remove [find where comment~"^{COMMENT_PREFIX}port:"]',
            f'/interface/bridge/remove [find where comment="{COMMENT_PREFIX}bridge"]',
        )
    ) + "\n"


def _reset_verdict(admin: base.LoopbackCHRAdmin) -> None:
    verdict_id = base._find_file_id(admin, VERDICT_FILE)
    if not verdict_id:
        raise CHRVlanBaselineError("VLAN verdict file disappeared")
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
        raise CHRVlanBaselineError("VLAN import dry-run changed RouterOS configuration")
    return {
        "apply": apply_result,
        "rollback": rollback_result,
        "configuration_unchanged": True,
        "configuration_sha256": before_digest,
    }


def _find_one(rows: list[Mapping[str, Any]], *, label: str, predicate) -> Mapping[str, Any]:
    matches = [row for row in rows if predicate(row)]
    if len(matches) != 1:
        raise CHRVlanBaselineError(f"expected one {label}, observed {len(matches)}")
    return matches[0]


def _csv_set(value: Any) -> set[str]:
    return {part.strip() for part in str(value or "").split(",") if part.strip()}


def _runtime_state(admin: base.LoopbackCHRAdmin) -> dict[str, Any]:
    bridge = _find_one(
        _records(admin, "interface/bridge"),
        label="managed bridge",
        predicate=lambda row: str(row.get("comment") or "") == COMMENT_PREFIX + "bridge",
    )
    if base._is_true(bridge.get("invalid")) or base._is_true(bridge.get("disabled")):
        raise CHRVlanBaselineError("managed bridge is invalid or disabled")
    if str(bridge.get("name") or "") != BRIDGE:
        raise CHRVlanBaselineError("managed bridge name mismatch")
    if str(bridge.get("vlan-filtering") or "").lower() not in {"true", "yes"}:
        raise CHRVlanBaselineError("managed bridge vlan-filtering is not enabled after activation")

    ports = [
        row for row in _records(admin, "interface/bridge/port")
        if str(row.get("comment") or "").startswith(COMMENT_PREFIX + "port:")
    ]
    if len(ports) != 2:
        raise CHRVlanBaselineError(f"expected two managed bridge ports, observed {len(ports)}")
    if any(base._is_true(row.get("invalid")) or base._is_true(row.get("disabled")) for row in ports):
        raise CHRVlanBaselineError("managed bridge port is invalid or disabled")
    by_interface = {str(row.get("interface") or ""): row for row in ports}
    if set(by_interface) != {TRUNK_PORT, ACCESS_PORT}:
        raise CHRVlanBaselineError(f"unexpected managed bridge ports: {sorted(by_interface)}")
    trunk = by_interface[TRUNK_PORT]
    access = by_interface[ACCESS_PORT]
    if (
        str(trunk.get("bridge") or "") != BRIDGE
        or str(trunk.get("frame-types") or "") != "admit-only-vlan-tagged"
    ):
        raise CHRVlanBaselineError("trunk port fields do not match rendered policy")
    if (
        str(access.get("bridge") or "") != BRIDGE
        or str(access.get("frame-types") or "") != "admit-only-untagged-and-priority-tagged"
        or str(access.get("pvid") or "") != str(USER_VLAN)
    ):
        raise CHRVlanBaselineError("access port fields do not match rendered policy")

    memberships = [
        row for row in _records(admin, "interface/bridge/vlan")
        if str(row.get("comment") or "").startswith(COMMENT_PREFIX + "membership:")
    ]
    if len(memberships) != 2:
        raise CHRVlanBaselineError(f"expected two managed bridge VLAN rows, observed {len(memberships)}")
    by_vlan = {str(row.get("vlan-ids") or ""): row for row in memberships}
    if set(by_vlan) != {str(MGMT_VLAN), str(USER_VLAN)}:
        raise CHRVlanBaselineError(f"unexpected managed VLAN ids: {sorted(by_vlan)}")
    mgmt_row = by_vlan[str(MGMT_VLAN)]
    user_row = by_vlan[str(USER_VLAN)]
    if not {BRIDGE, TRUNK_PORT}.issubset(_csv_set(mgmt_row.get("tagged"))):
        raise CHRVlanBaselineError("management VLAN is not tagged on bridge CPU and trunk")
    if TRUNK_PORT not in _csv_set(user_row.get("tagged")):
        raise CHRVlanBaselineError("user VLAN is not tagged on trunk")
    if ACCESS_PORT not in _csv_set(user_row.get("untagged")):
        raise CHRVlanBaselineError("user VLAN is not untagged on access port")

    vlan_interface = _find_one(
        _records(admin, "interface/vlan"),
        label="management VLAN interface",
        predicate=lambda row: str(row.get("comment") or "") == COMMENT_PREFIX + "management-interface",
    )
    if (
        str(vlan_interface.get("name") or "") != MGMT_INTERFACE
        or str(vlan_interface.get("interface") or "") != BRIDGE
        or str(vlan_interface.get("vlan-id") or "") != str(MGMT_VLAN)
        or base._is_true(vlan_interface.get("invalid"))
        or base._is_true(vlan_interface.get("disabled"))
    ):
        raise CHRVlanBaselineError("management VLAN interface does not match rendered policy")

    address = _find_one(
        _records(admin, "ip/address"),
        label="management VLAN address",
        predicate=lambda row: str(row.get("comment") or "") == COMMENT_PREFIX + "management-address",
    )
    if (
        str(address.get("address") or "") != MGMT_ADDRESS
        or str(address.get("interface") or "") != MGMT_INTERFACE
        or base._is_true(address.get("invalid"))
        or base._is_true(address.get("disabled"))
    ):
        raise CHRVlanBaselineError("management VLAN address does not match rendered policy")

    # OOB management path itself must remain outside the managed bridge.
    if any(
        str(row.get("interface") or "") == OOB_MANAGEMENT
        and str(row.get("bridge") or "") == BRIDGE
        for row in _records(admin, "interface/bridge/port")
    ):
        raise CHRVlanBaselineError("OOB management interface was unexpectedly added to the managed bridge")

    admin.request("GET", "system/resource")
    return {
        "managed_bridge_count": 1,
        "managed_bridge_port_count": 2,
        "managed_bridge_vlan_count": 2,
        "managed_vlan_interface_count": 1,
        "managed_management_address_count": 1,
        "invalid_managed_objects": 0,
        "disabled_managed_objects": 0,
        "vlan_filtering_enabled": True,
        "trunk_membership_exact": True,
        "access_pvid_exact": True,
        "management_vlan_interface_exact": True,
        "oob_management_interface_untouched": True,
        "management_rest_reachable_after_apply": True,
        "in_band_vlan_data_plane_claimed": False,
    }


def verify_vlan_baseline(*, admin_url: str) -> dict[str, Any]:
    admin = base.LoopbackCHRAdmin(admin_url)
    platform = admin.assert_disposable_chr()

    state = _live_state(admin)
    interface_names = {
        str(row.get("name") or "")
        for row in state["interfaces"]
        if isinstance(row, Mapping)
    }
    missing = sorted({OOB_MANAGEMENT, TRUNK_PORT, ACCESS_PORT} - interface_names)
    if missing:
        raise CHRVlanBaselineError(f"disposable CHR is missing VLAN fixture interfaces: {missing}")
    _assert_synthetic_management_network_is_free(state)
    prerequisites = _live_prerequisites(admin)
    if not _owned_objects_absent(admin):
        raise CHRVlanBaselineError("disposable CHR baseline already contains routercfg-owned VLAN objects")

    ir = _build_ir()
    plan = render_routeros_vlan(
        ir=ir,
        state=state,
        prerequisites=prerequisites,
        management_path=_management_path(),
    ).as_dict()
    commands = plan.get("commands")
    if not isinstance(commands, list) or len(commands) != 9:
        raise CHRVlanBaselineError(
            f"VLAN CHR fixture requires exactly nine generated commands, observed {len(commands) if isinstance(commands, list) else 'invalid'}"
        )
    if str(commands[-1].get("command_id") or "") != "vlan.99.activate-filtering":
        raise CHRVlanBaselineError("VLAN filtering activation is not the final generated command")

    apply_script = "\n".join(str(row["command"]) for row in commands) + "\n"
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
            raise CHRVlanBaselineError("VLAN apply did not change the configuration digest")
        runtime = _runtime_state(admin)

        chunked._create_text_file_chunk_verified(admin, ROLLBACK_FILE, rollback_script)
        rollback_result = mutation._execute_import(admin, file_name=ROLLBACK_FILE, expect_success=True)
        if not _owned_objects_absent(admin):
            raise CHRVlanBaselineError("routercfg-owned VLAN objects remain after rollback")
        rollback_digest = base._canonical_digest(_configuration_snapshot(admin))
        if rollback_digest != baseline_digest:
            raise CHRVlanBaselineError("VLAN rollback did not restore the exact baseline digest")
    finally:
        for name in TEMP_FILES:
            base._delete_file_if_present(admin, name)
        base._assert_files_absent(admin, TEMP_FILES)

    return {
        "ok": True,
        "acceptance": "PASS",
        "scope": "disposable_chr_vlan_management_survival_and_rollback",
        "platform": {
            "version": str(platform.get("version") or ""),
            "architecture": str(platform.get("architecture-name") or ""),
            "board_name": str(platform.get("board-name") or ""),
        },
        "fixture": {
            "kind": "lab_only_three_interface_rfc5737_management_vlan",
            "oob_management_interface": OOB_MANAGEMENT,
            "trunk_port": TRUNK_PORT,
            "access_port": ACCESS_PORT,
            "management_vlan": MGMT_VLAN,
            "user_vlan": USER_VLAN,
            "management_address": MGMT_ADDRESS,
            "command_count": len(commands),
        },
        "renderer_input": {
            "interfaces_source": "live_chr",
            "ip_addresses_source": "live_chr",
            "switching_prerequisites_source": "live_chr",
            "management_path_source": "lab_oob_loopback_rest_via_ether1",
            "plan_sha256": str(plan.get("plan_sha256") or ""),
            "activation_last_command_id": str(plan.get("activation_last_command_id") or ""),
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
        "in_band_vlan_data_plane_acceptance": False,
        "production_writer_available": False,
        "transport_exposed_to_product": False,
        "write_authorized": False,
        "physical_router_targeted": False,
    }


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Validate RouterOS VLAN management-survival generation on disposable official CHR"
    )
    parser.add_argument("--admin-url", default="http://127.0.0.1:9880")
    parser.add_argument("--output", required=True)
    args = parser.parse_args()

    output = Path(args.output)
    output.parent.mkdir(parents=True, exist_ok=True)
    try:
        result = verify_vlan_baseline(admin_url=args.admin_url)
        rc = 0
    except (OSError, base.CHRRenderDryRunError, mutation.CHRMutationRollbackError, CHRVlanBaselineError) as exc:
        result = {
            "ok": False,
            "acceptance": "FAIL",
            "error": str(exc),
            "in_band_vlan_data_plane_acceptance": False,
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
