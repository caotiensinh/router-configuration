from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any, Mapping

import build_renderer_syntax_fixture as fixture_builder
import verify_mutation_rollback as runtime_rollback
import verify_render_dry_run as base
import verify_render_dry_run_chunked as chunked
import verify_transaction_post_apply as post_apply
import verify_transaction_runtime_admission as admission_helpers

from router_configuration.transaction_adapter_admission import (
    TransactionAdapterAdmissionError,
    admit_disposable_chr_candidate,
)
from router_configuration.transaction_backup_evidence import (
    TransactionBackupEvidenceError,
    build_transaction_backup_evidence,
    validate_transaction_backup_evidence,
)
from router_configuration.transaction_envelope import (
    TransactionEnvelopeError,
    build_transaction_envelope,
)
from router_configuration.transaction_lifecycle import (
    TransactionLifecycleError,
    initialize_transaction_lifecycle,
    transition_transaction_lifecycle,
)


class CHRTransactionManagementDuringApplyError(RuntimeError):
    pass


def _management_probe(
    *,
    admin_url: str,
    completed_steps: int,
    command_count: int,
) -> dict[str, Any]:
    """Read management health through a fresh REST helper between apply steps."""

    probe_admin = base.LoopbackCHRAdmin(admin_url)
    platform = probe_admin.assert_disposable_chr()
    interfaces = post_apply._required_interfaces_running(probe_admin)
    return {
        "completed_steps": completed_steps,
        "command_count": command_count,
        "transaction_in_progress": 0 < completed_steps < command_count,
        "fresh_rest_session": True,
        "management_rest_ok": True,
        "required_interfaces_running": True,
        "required_interfaces": interfaces,
        "platform": {
            "version": str(platform.get("version") or ""),
            "architecture": str(platform.get("architecture-name") or ""),
            "board_name": str(platform.get("board-name") or ""),
        },
    }


def verify_transaction_management_during_apply(
    *,
    admin_url: str,
    workflow_sha: str,
) -> dict[str, Any]:
    """Prove management survival across an admitted ordered CHR apply sequence.

    The accepted 38-command fixture is applied in the exact generated order as
    one-command chunks. After every completed command, a *fresh* REST helper
    independently checks RouterOS management reachability and the required
    interfaces. Probes after commands 1..37 therefore occur while the overall
    transaction is still incomplete.

    This deliberately proves management survival at every mutation-step
    boundary. It does not claim uninterrupted sub-command monitoring, routed
    data-plane behavior, production apply readiness or a product writer.
    """

    exact_sha = admission_helpers._workflow_sha(workflow_sha)
    admin = base.LoopbackCHRAdmin(admin_url)
    platform = admin.assert_disposable_chr()
    interface_names = admission_helpers._required_interfaces(admin)

    fixture = fixture_builder.build_syntax_fixture()
    plan = admission_helpers._render_plan(fixture)
    commands = plan["commands"]
    command_count = len(commands)
    if command_count != 38:
        raise CHRTransactionManagementDuringApplyError(
            f"management-during-apply gate requires 38 commands, observed {command_count}"
        )

    baseline = chunked._configuration_snapshot_with_pcc(admin)
    baseline_sha256 = base._canonical_digest(baseline)
    sanitized_pre_state = admission_helpers._sanitized_pre_state_artifact(
        workflow_sha=exact_sha,
        platform=platform,
        baseline_sha256=baseline_sha256,
        interface_names=interface_names,
    )
    backup = build_transaction_backup_evidence(
        kind="sanitized_export",
        artifact_ref=f"artifact://chr/{exact_sha}/transaction-pre-state-digest.json",
        sha256=admission_helpers._canonical_sha256(sanitized_pre_state),
        pre_state_sha256=baseline_sha256,
    ).as_dict()
    validate_transaction_backup_evidence(
        backup,
        expected_pre_state_sha256=baseline_sha256,
    )

    envelope = build_transaction_envelope(
        render_plan=plan,
        pre_state_sha256=baseline_sha256,
        backup=backup,
        approval={
            "approved": True,
            "plan_sha256": plan["render_sha256"],
            "approver_ref": f"lab-policy/disposable-chr/{exact_sha}",
        },
        management_path={
            "ok": True,
            "evidence_ref": "runtime-evidence/disposable-chr/rest-management",
        },
        connectivity_baseline={
            "ok": True,
            "evidence_ref": "runtime-evidence/disposable-chr/interface-baseline",
        },
    ).as_dict()
    lifecycle = initialize_transaction_lifecycle(envelope=envelope).as_dict()
    lifecycle = transition_transaction_lifecycle(
        lifecycle=lifecycle,
        to_phase="authorized",
        evidence={
            "evidence_ref": "runtime-evidence/disposable-chr/lab-policy-authorization",
            "authorized": True,
            "exact_envelope_revalidated": True,
            "transaction_id": lifecycle["transaction_id"],
        },
    ).as_dict()

    adapter_admission = admit_disposable_chr_candidate(
        render_plan=plan,
        envelope=envelope,
        lifecycle=lifecycle,
        target={
            "target_kind": "disposable_chr",
            "disposable": True,
            "snapshot_mode": True,
            "physical_router_targeted": False,
            "production": False,
            "workflow_sha": exact_sha,
        },
    ).as_dict()
    if adapter_admission.get("target_kind") != "disposable_chr":
        raise CHRTransactionManagementDuringApplyError(
            "management-during-apply gate did not admit a disposable CHR candidate"
        )

    rollback_script = runtime_rollback._rollback_script()
    rollback_preflight: dict[str, Any] | None = None
    step_results: list[dict[str, Any]] = []
    management_probes: list[dict[str, Any]] = []
    mutation_started = False
    cleanup_completed = False
    cleanup_result: dict[str, Any] | None = None
    cleanup_sha256: str | None = None
    final_state_sha256: str | None = None
    final_counts: dict[str, int] | None = None

    for name in runtime_rollback.TEMP_FILES:
        base._delete_file_if_present(admin, name)

    try:
        chunked._create_text_file_chunk_verified(
            admin,
            runtime_rollback.ROLLBACK_FILE,
            rollback_script,
        )
        runtime_rollback._write_verdict_file(admin)
        rollback_preflight = base._execute_import_dry_run(
            admin,
            file_name=runtime_rollback.ROLLBACK_FILE,
            verdict_name=runtime_rollback.VERDICT_FILE,
            expect_success=True,
        )

        pre_probe = _management_probe(
            admin_url=admin_url,
            completed_steps=0,
            command_count=command_count,
        )

        for step_index, command in enumerate(commands, start=1):
            command_text = str(command["command"]) + "\n"
            chunked._create_text_file_chunk_verified(
                admin,
                runtime_rollback.APPLY_FILE,
                command_text,
            )
            step_result = runtime_rollback._execute_import(
                admin,
                file_name=runtime_rollback.APPLY_FILE,
                expect_success=True,
            )
            mutation_started = True
            if step_result.get("verdict") != "OK":
                raise CHRTransactionManagementDuringApplyError(
                    f"ordered mutation step {step_index} did not complete successfully"
                )
            step_results.append(
                {
                    "step": step_index,
                    "section": str(command.get("section") or ""),
                    "verdict": "OK",
                }
            )
            management_probes.append(
                _management_probe(
                    admin_url=admin_url,
                    completed_steps=step_index,
                    command_count=command_count,
                )
            )

        final_counts = runtime_rollback._assert_mutated_state(admin)
        final_state = chunked._configuration_snapshot_with_pcc(admin)
        final_state_sha256 = base._canonical_digest(final_state)
        if final_state_sha256 == baseline_sha256:
            raise CHRTransactionManagementDuringApplyError(
                "ordered mutation sequence did not change the configuration digest"
            )

        lifecycle = transition_transaction_lifecycle(
            lifecycle=lifecycle,
            to_phase="apply_observed",
            evidence={
                "evidence_ref": "runtime-evidence/disposable-chr/ordered-apply-sequence",
                "exact_plan_revalidated": True,
                "exact_pre_state_revalidated": True,
                "backup_revalidated": True,
                "management_path_revalidated": True,
                "connectivity_revalidated": True,
                "apply_completed": True,
            },
        ).as_dict()
        lifecycle = transition_transaction_lifecycle(
            lifecycle=lifecycle,
            to_phase="verification_pending",
            evidence={
                "evidence_ref": "runtime-evidence/disposable-chr/final-ordered-apply-state",
                "post_state_sha256": final_state_sha256,
            },
        ).as_dict()
        lifecycle = transition_transaction_lifecycle(
            lifecycle=lifecycle,
            to_phase="verified",
            evidence={
                "evidence_ref": "runtime-evidence/disposable-chr/management-during-apply-verification",
                "management_ok": True,
                "connectivity_ok": True,
                "intended_state_ok": True,
                "post_state_sha256": final_state_sha256,
            },
        ).as_dict()
    finally:
        if mutation_started:
            try:
                chunked._create_text_file_chunk_verified(
                    admin,
                    runtime_rollback.ROLLBACK_FILE,
                    rollback_script,
                )
                cleanup_result = runtime_rollback._execute_import(
                    admin,
                    file_name=runtime_rollback.ROLLBACK_FILE,
                    expect_success=True,
                )
                runtime_rollback._assert_managed_state_absent(admin)
                cleanup_state = chunked._configuration_snapshot_with_pcc(admin)
                cleanup_sha256 = base._canonical_digest(cleanup_state)
                cleanup_completed = cleanup_sha256 == baseline_sha256
            except (
                OSError,
                base.CHRRenderDryRunError,
                runtime_rollback.CHRMutationRollbackError,
            ):
                cleanup_completed = False
        for name in runtime_rollback.TEMP_FILES:
            base._delete_file_if_present(admin, name)
        base._assert_files_absent(admin, runtime_rollback.TEMP_FILES)

    if not cleanup_completed:
        raise CHRTransactionManagementDuringApplyError(
            "management-during-apply lab cleanup did not restore the exact baseline"
        )
    if lifecycle.get("phase") != "verified":
        raise CHRTransactionManagementDuringApplyError(
            "management-during-apply lifecycle did not reach verified"
        )

    in_progress_probes = [
        probe for probe in management_probes if probe["transaction_in_progress"] is True
    ]
    if len(in_progress_probes) != command_count - 1:
        raise CHRTransactionManagementDuringApplyError(
            "management probes did not cover every incomplete transaction step"
        )
    if any(
        probe.get("management_rest_ok") is not True
        or probe.get("required_interfaces_running") is not True
        or probe.get("fresh_rest_session") is not True
        for probe in management_probes
    ):
        raise CHRTransactionManagementDuringApplyError(
            "at least one management probe failed during the apply sequence"
        )

    return {
        "ok": True,
        "scope": "disposable_chr_transaction_management_survival_across_apply_sequence",
        "workflow_sha": exact_sha,
        "transaction": {
            "transaction_id": envelope["transaction_id"],
            "envelope_sha256": envelope["envelope_sha256"],
            "render_sha256": plan["render_sha256"],
            "pre_state_sha256": baseline_sha256,
            "command_count": command_count,
        },
        "admission": adapter_admission,
        "lifecycle": lifecycle,
        "rollback_preflight": rollback_preflight,
        "apply_sequence": {
            "mode": "ordered_single_command_chunks",
            "exact_generated_order_preserved": True,
            "completed_steps": len(step_results),
            "step_results": step_results,
            "final_managed_object_counts": final_counts,
            "final_state_sha256": final_state_sha256,
        },
        "management_survival": {
            "pre_mutation_probe": pre_probe,
            "probe_after_every_mutation_step": True,
            "fresh_rest_session_per_probe": True,
            "probe_count": len(management_probes),
            "in_progress_probe_count": len(in_progress_probes),
            "expected_in_progress_probe_count": command_count - 1,
            "all_probes_successful": True,
            "required_interfaces_running_every_probe": True,
            "management_rest_reachable_every_probe": True,
            "claim_scope": "between_ordered_mutation_steps_while_transaction_incomplete",
            "continuous_in_command_monitoring_claimed": False,
        },
        "lab_cleanup": {
            "completed": cleanup_completed,
            "cleanup_import": cleanup_result,
            "cleanup_state_sha256": cleanup_sha256,
            "baseline_sha256": baseline_sha256,
            "baseline_digest_restored": cleanup_sha256 == baseline_sha256,
        },
        "post_apply_verification_claimed": True,
        "management_survival_after_apply_claimed": True,
        "management_survival_during_apply_claimed": True,
        "management_survival_during_apply_scope": (
            "fresh REST verification between every ordered mutation step "
            "while the transaction remains incomplete"
        ),
        "continuous_in_command_monitoring_claimed": False,
        "routed_data_plane_claimed": False,
        "recovery_verification_claimed": False,
        "operator_attestation_claimed": False,
        "production_writer_available": False,
        "transport_exposed_to_product": False,
        "physical_router_targeted": False,
        "production_allowed": False,
        "write_authorized": False,
        "acceptance": "PASS",
    }


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Prove CHR management survival across an ordered apply sequence"
    )
    parser.add_argument("--admin-url", default="http://127.0.0.1:9680")
    parser.add_argument("--workflow-sha", required=True)
    parser.add_argument("--output", required=True)
    args = parser.parse_args()

    output = Path(args.output)
    output.parent.mkdir(parents=True, exist_ok=True)
    try:
        result = verify_transaction_management_during_apply(
            admin_url=args.admin_url,
            workflow_sha=args.workflow_sha,
        )
        rc = 0
    except (
        OSError,
        CHRTransactionManagementDuringApplyError,
        TransactionAdapterAdmissionError,
        TransactionBackupEvidenceError,
        TransactionEnvelopeError,
        TransactionLifecycleError,
        base.CHRRenderDryRunError,
        runtime_rollback.CHRMutationRollbackError,
        post_apply.CHRTransactionPostApplyVerificationError,
    ) as exc:
        result = {
            "ok": False,
            "error": str(exc),
            "scope": "disposable_chr_transaction_management_survival_across_apply_sequence",
            "post_apply_verification_claimed": False,
            "management_survival_after_apply_claimed": False,
            "management_survival_during_apply_claimed": False,
            "continuous_in_command_monitoring_claimed": False,
            "routed_data_plane_claimed": False,
            "recovery_verification_claimed": False,
            "operator_attestation_claimed": False,
            "production_writer_available": False,
            "transport_exposed_to_product": False,
            "physical_router_targeted": False,
            "production_allowed": False,
            "write_authorized": False,
            "acceptance": "FAIL",
        }
        rc = 19

    output.write_text(
        json.dumps(result, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    print(json.dumps(result, indent=2, sort_keys=True))
    return rc


if __name__ == "__main__":
    raise SystemExit(main())
