from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any, Mapping

import vlan_baseline_core as core

# Re-export the stable fixture/helper contract used by unit tests and operators.
BRIDGE = core.BRIDGE
MGMT_INTERFACE = core.MGMT_INTERFACE
MGMT_ADDRESS = core.MGMT_ADDRESS
MGMT_VLAN = core.MGMT_VLAN
USER_VLAN = core.USER_VLAN
TRUNK_PORT = core.TRUNK_PORT
ACCESS_PORT = core.ACCESS_PORT
OOB_MANAGEMENT = core.OOB_MANAGEMENT
COMMENT_PREFIX = core.COMMENT_PREFIX
render_routeros_vlan = core.render_routeros_vlan
_build_ir = core._build_ir
_management_path = core._management_path
_rollback_script = core._rollback_script


def verify_vlan_baseline(*, admin_url: str) -> dict[str, Any]:
    '''Run the accepted VLAN core with the corrected eight-command fixture contract.

    The core owns live-state collection, dry-run, runtime assertions, management
    survival checks and owned-only rollback. This runner intentionally changes
    only the stale fixture command-count assertion that previously failed before
    apply.
    '''

    admin = core.base.LoopbackCHRAdmin(admin_url)
    platform = admin.assert_disposable_chr()

    state = core._live_state(admin)
    interface_names = {
        str(row.get("name") or "")
        for row in state["interfaces"]
        if isinstance(row, Mapping)
    }
    missing = sorted({OOB_MANAGEMENT, TRUNK_PORT, ACCESS_PORT} - interface_names)
    if missing:
        raise core.CHRVlanBaselineError(
            f"disposable CHR is missing VLAN fixture interfaces: {missing}"
        )
    core._assert_synthetic_management_network_is_free(state)
    prerequisites = core._live_prerequisites(admin)
    if not core._owned_objects_absent(admin):
        raise core.CHRVlanBaselineError(
            "disposable CHR baseline already contains routercfg-owned VLAN objects"
        )

    ir = _build_ir()
    plan = render_routeros_vlan(
        ir=ir,
        state=state,
        prerequisites=prerequisites,
        management_path=_management_path(),
    ).as_dict()
    commands = plan.get("commands")
    if not isinstance(commands, list) or len(commands) != 8:
        raise core.CHRVlanBaselineError(
            "VLAN CHR fixture requires exactly eight generated commands, observed "
            + str(len(commands) if isinstance(commands, list) else "invalid")
        )
    if str(commands[-1].get("command_id") or "") != "vlan.99.activate-filtering":
        raise core.CHRVlanBaselineError(
            "VLAN filtering activation is not the final generated command"
        )

    apply_script = "\n".join(str(row["command"]) for row in commands) + "\n"
    rollback_script = _rollback_script()
    for name in core.TEMP_FILES:
        core.base._delete_file_if_present(admin, name)

    baseline = core._configuration_snapshot(admin)
    baseline_digest = core.base._canonical_digest(baseline)
    dry_run_result: dict[str, Any] | None = None
    apply_result: dict[str, Any] | None = None
    rollback_result: dict[str, Any] | None = None
    runtime: dict[str, Any] | None = None
    mutated_digest: str | None = None
    rollback_digest: str | None = None

    try:
        dry_run_result = core._dry_run(
            admin, apply_script=apply_script, rollback_script=rollback_script
        )
        core.chunked._create_text_file_chunk_verified(admin, core.APPLY_FILE, apply_script)
        apply_result = core.mutation._execute_import(
            admin, file_name=core.APPLY_FILE, expect_success=True
        )
        mutated_digest = core.base._canonical_digest(core._configuration_snapshot(admin))
        if mutated_digest == baseline_digest:
            raise core.CHRVlanBaselineError(
                "VLAN apply did not change the configuration digest"
            )
        runtime = core._runtime_state(admin)

        core.chunked._create_text_file_chunk_verified(
            admin, core.ROLLBACK_FILE, rollback_script
        )
        rollback_result = core.mutation._execute_import(
            admin, file_name=core.ROLLBACK_FILE, expect_success=True
        )
        if not core._owned_objects_absent(admin):
            raise core.CHRVlanBaselineError(
                "routercfg-owned VLAN objects remain after rollback"
            )
        rollback_digest = core.base._canonical_digest(core._configuration_snapshot(admin))
        if rollback_digest != baseline_digest:
            raise core.CHRVlanBaselineError(
                "VLAN rollback did not restore the exact baseline digest"
            )
    finally:
        for name in core.TEMP_FILES:
            core.base._delete_file_if_present(admin, name)
        core.base._assert_files_absent(admin, core.TEMP_FILES)

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
    except (
        OSError,
        core.base.CHRRenderDryRunError,
        core.mutation.CHRMutationRollbackError,
        core.CHRVlanBaselineError,
    ) as exc:
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

    output.write_text(
        json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    print(json.dumps(result, indent=2, sort_keys=True))
    return rc


if __name__ == "__main__":
    raise SystemExit(main())
