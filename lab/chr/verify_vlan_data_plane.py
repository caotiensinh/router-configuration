from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any, Mapping

import vlan_baseline_core as core


class CHRVlanDataPlaneError(RuntimeError):
    pass


def _load(path: str) -> dict[str, Any]:
    return json.loads(Path(path).read_text(encoding="utf-8"))


def _assert_positive_flow(payload: Mapping[str, Any]) -> dict[str, Any]:
    requested = int(payload.get("requested_flows") or 0)
    successful = int(payload.get("successful_flows") or 0)
    tags = payload.get("tags")
    normalized = {str(k): int(v) for k, v in tags.items()} if isinstance(tags, Mapping) else {}
    if requested <= 0 or successful != requested or normalized != {"VLAN20": requested}:
        raise CHRVlanDataPlaneError(
            f"tagged VLAN20 flow failed: requested={requested} successful={successful} tags={normalized}"
        )
    return {
        "requested_flows": requested,
        "successful_flows": successful,
        "success_ratio": 1.0,
        "observed_tags": normalized,
    }


def _assert_negative_flow(payload: Mapping[str, Any]) -> dict[str, Any]:
    requested = int(payload.get("requested_flows") or 0)
    successful = int(payload.get("successful_flows") or 0)
    failed = int(payload.get("failed_flows") or 0)
    tags = payload.get("tags")
    normalized = {str(k): int(v) for k, v in tags.items()} if isinstance(tags, Mapping) else {}
    if requested <= 0 or successful != 0 or failed != requested or normalized:
        raise CHRVlanDataPlaneError(
            f"untagged trunk negative control was not blocked: requested={requested} successful={successful} failed={failed} tags={normalized}"
        )
    return {
        "requested_flows": requested,
        "successful_flows": 0,
        "failed_flows": failed,
        "success_ratio": 0.0,
        "observed_tags": {},
        "blocked_as_expected": True,
    }


def prepare(*, admin_url: str, workflow_sha: str) -> dict[str, Any]:
    admin = core.base.LoopbackCHRAdmin(admin_url)
    platform = admin.assert_disposable_chr()
    state = core._live_state(admin)
    interface_names = {
        str(row.get("name") or "")
        for row in state["interfaces"]
        if isinstance(row, Mapping)
    }
    missing = sorted({core.OOB_MANAGEMENT, core.TRUNK_PORT, core.ACCESS_PORT} - interface_names)
    if missing:
        raise CHRVlanDataPlaneError(f"disposable CHR is missing VLAN data-plane interfaces: {missing}")
    core._assert_synthetic_management_network_is_free(state)
    if not core._owned_objects_absent(admin):
        raise CHRVlanDataPlaneError("disposable CHR baseline already contains routercfg-owned VLAN objects")

    plan = core.render_routeros_vlan(
        ir=core._build_ir(),
        state=state,
        prerequisites=core._live_prerequisites(admin),
        management_path=core._management_path(),
    ).as_dict()
    commands = plan.get("commands")
    if not isinstance(commands, list) or len(commands) != 8:
        raise CHRVlanDataPlaneError("VLAN data-plane gate requires exactly eight production-renderer commands")
    if str(commands[-1].get("command_id") or "") != "vlan.99.activate-filtering":
        raise CHRVlanDataPlaneError("VLAN filtering activation is not the final generated command")

    for name in core.TEMP_FILES:
        core.base._delete_file_if_present(admin, name)
    baseline_digest = core.base._canonical_digest(core._configuration_snapshot(admin))
    apply_script = "\n".join(str(row["command"]) for row in commands) + "\n"
    core.chunked._create_text_file_chunk_verified(admin, core.APPLY_FILE, apply_script)
    apply_result = core.mutation._execute_import(admin, file_name=core.APPLY_FILE, expect_success=True)
    mutated_digest = core.base._canonical_digest(core._configuration_snapshot(admin))
    if mutated_digest == baseline_digest:
        raise CHRVlanDataPlaneError("VLAN data-plane apply did not change the RouterOS configuration")
    runtime = core._runtime_state(admin)
    core.base._delete_file_if_present(admin, core.APPLY_FILE)
    core.base._delete_file_if_present(admin, core.mutation.VERDICT_FILE)

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
            "trunk_port": core.TRUNK_PORT,
            "access_port": core.ACCESS_PORT,
            "user_vlan": core.USER_VLAN,
            "management_vlan": core.MGMT_VLAN,
            "command_count": 8,
            "activation_last": True,
        },
        "renderer": {
            "production_renderer_used": True,
            "plan_sha256": str(plan.get("plan_sha256") or ""),
            "activation_last_command_id": str(plan.get("activation_last_command_id") or ""),
        },
        "runtime": runtime,
        "apply": {"verdict": str(apply_result.get("verdict") or "")},
        "configuration_baseline_sha256": baseline_digest,
        "configuration_mutated_sha256": mutated_digest,
        "production_writer_available": False,
        "transport_exposed_to_product": False,
        "write_authorized": False,
        "physical_router_targeted": False,
    }


def finalize(
    *,
    admin_url: str,
    prepared: Mapping[str, Any],
    tagged_flow: Mapping[str, Any],
    untagged_flow: Mapping[str, Any],
) -> dict[str, Any]:
    admin = core.base.LoopbackCHRAdmin(admin_url)
    admin.assert_disposable_chr()
    positive = _assert_positive_flow(tagged_flow)
    negative = _assert_negative_flow(untagged_flow)

    rollback_script = core._rollback_script()
    core.chunked._create_text_file_chunk_verified(admin, core.ROLLBACK_FILE, rollback_script)
    rollback_result = core.mutation._execute_import(admin, file_name=core.ROLLBACK_FILE, expect_success=True)
    if not core._owned_objects_absent(admin):
        raise CHRVlanDataPlaneError("routercfg-owned VLAN objects remain after data-plane rollback")
    rollback_digest = core.base._canonical_digest(core._configuration_snapshot(admin))
    baseline_digest = str(prepared.get("configuration_baseline_sha256") or "")
    if rollback_digest != baseline_digest:
        raise CHRVlanDataPlaneError("VLAN data-plane rollback did not restore exact baseline digest")
    for name in core.TEMP_FILES:
        core.base._delete_file_if_present(admin, name)
    core.base._assert_files_absent(admin, core.TEMP_FILES)

    return {
        "ok": True,
        "acceptance": "PASS",
        "scope": "disposable_chr_vlan20_tagged_to_access_data_plane",
        "workflow_sha": str(prepared.get("workflow_sha") or ""),
        "platform": dict(prepared.get("platform") or {}),
        "renderer": dict(prepared.get("renderer") or {}),
        "packet_flow": {
            "tagged_trunk_to_access": positive,
            "untagged_trunk_negative_control": negative,
        },
        "in_band_vlan_data_plane_acceptance": True,
        "ingress_filter_negative_control_acceptance": True,
        "rollback": {"verdict": str(rollback_result.get("verdict") or "")},
        "configuration_baseline_sha256": baseline_digest,
        "configuration_rollback_sha256": rollback_digest,
        "rollback_digest_restored": True,
        "temporary_files_removed": True,
        "production_writer_available": False,
        "transport_exposed_to_product": False,
        "write_authorized": False,
        "physical_router_targeted": False,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description="Prove RouterOS VLAN in-band packet flow on disposable CHR")
    sub = parser.add_subparsers(dest="command", required=True)
    p_prepare = sub.add_parser("prepare")
    p_prepare.add_argument("--admin-url", default="http://127.0.0.1:10180")
    p_prepare.add_argument("--workflow-sha", required=True)
    p_prepare.add_argument("--output", required=True)
    p_final = sub.add_parser("finalize")
    p_final.add_argument("--admin-url", default="http://127.0.0.1:10180")
    p_final.add_argument("--prepared", required=True)
    p_final.add_argument("--tagged-flow", required=True)
    p_final.add_argument("--untagged-flow", required=True)
    p_final.add_argument("--output", required=True)
    args = parser.parse_args()
    output = Path(args.output)
    output.parent.mkdir(parents=True, exist_ok=True)
    try:
        if args.command == "prepare":
            result = prepare(admin_url=args.admin_url, workflow_sha=args.workflow_sha)
        else:
            result = finalize(
                admin_url=args.admin_url,
                prepared=_load(args.prepared),
                tagged_flow=_load(args.tagged_flow),
                untagged_flow=_load(args.untagged_flow),
            )
        rc = 0
    except (
        OSError,
        core.base.CHRRenderDryRunError,
        core.mutation.CHRMutationRollbackError,
        core.CHRVlanBaselineError,
        CHRVlanDataPlaneError,
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
        rc = 1
    output.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(json.dumps(result, indent=2, sort_keys=True))
    return rc


if __name__ == "__main__":
    raise SystemExit(main())
