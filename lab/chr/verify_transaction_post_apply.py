from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any, Mapping

import build_renderer_syntax_fixture as fixture_builder
import verify_mutation_rollback as runtime_rollback
import verify_render_dry_run as base
import verify_render_dry_run_chunked as chunked
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


class CHRTransactionPostApplyVerificationError(RuntimeError):
    pass


_REQUIRED_INTERFACES = {"ether1", "ether2", "ether3"}


def _required_interfaces_running(admin: base.LoopbackCHRAdmin) -> list[str]:
    _, payload = admin.request("GET", "interface")
    rows = {
        str(row.get("name") or ""): row
        for row in base._rows(payload)
        if isinstance(row, Mapping)
    }
    missing = sorted(_REQUIRED_INTERFACES - set(rows))
    if missing:
        raise CHRTransactionPostApplyVerificationError(
            f"post-apply verification is missing required interfaces: {missing}"
        )
    unhealthy = sorted(
        name
        for name in _REQUIRED_INTERFACES
        if str(rows[name].get("running") or "").lower() != "true"
        or str(rows[name].get("disabled") or "").lower() == "true"
    )
    if unhealthy:
        raise CHRTransactionPostApplyVerificationError(
            f"required interfaces are not operational after apply: {unhealthy}"
        )
    return sorted(_REQUIRED_INTERFACES)


def verify_transaction_post_apply(
    *,
    admin_url: str,
    workflow_sha: str,
) -> dict[str, Any]:
    """Prove the admitted disposable-CHR success path with an independent read.

    This lab-only gate admits the same accepted 38-command transaction fixture,
    applies it once, then creates a fresh RouterOS REST helper. Only the fresh
    helper may supply post-apply verification evidence. The lifecycle advances
    through ``verification_pending`` to ``verified`` only after management REST,
    required-interface operational state, intended managed-object counts and the
    independently observed post-state digest all agree.

    The verified transaction is then cleaned from the disposable CHR solely as
    test hygiene. Cleanup does not rewrite the successful lifecycle as rollback.
    No product transport or production writer is exposed by this module.
    """

    exact_sha = admission_helpers._workflow_sha(workflow_sha)
    admin = base.LoopbackCHRAdmin(admin_url)
    platform = admin.assert_disposable_chr()
    interface_names = admission_helpers._required_interfaces(admin)

    fixture = fixture_builder.build_syntax_fixture()
    plan = admission_helpers._render_plan(fixture)
    commands = plan["commands"]
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
        raise CHRTransactionPostApplyVerificationError(
            "post-apply gate did not admit a disposable CHR candidate"
        )

    apply_script = "\n".join(str(item["command"]) for item in commands) + "\n"
    rollback_script = runtime_rollback._rollback_script()
    applied = False
    cleanup_completed = False
    cleanup_result: dict[str, Any] | None = None
    cleanup_sha256: str | None = None
    rollback_preflight: dict[str, Any] | None = None
    apply_result: dict[str, Any] | None = None
    observed_post_sha256: str | None = None
    verified_post_sha256: str | None = None
    verified_counts: dict[str, int] | None = None
    verified_interfaces: list[str] | None = None
    verification_platform: Mapping[str, Any] | None = None

    for name in runtime_rollback.TEMP_FILES:
        base._delete_file_if_present(admin, name)

    try:
        # Prove cleanup syntax before mutation, then revalidate the same lab
        # management surface immediately before the only mutation-capable step.
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
        admission_helpers._required_interfaces(admin)

        chunked._create_text_file_chunk_verified(
            admin,
            runtime_rollback.APPLY_FILE,
            apply_script,
        )
        apply_result = runtime_rollback._execute_import(
            admin,
            file_name=runtime_rollback.APPLY_FILE,
            expect_success=True,
        )
        applied = True
        if apply_result.get("verdict") != "OK":
            raise CHRTransactionPostApplyVerificationError(
                "admitted transaction apply was not observed as successful"
            )

        observed_counts = runtime_rollback._assert_mutated_state(admin)
        observed_post_state = chunked._configuration_snapshot_with_pcc(admin)
        observed_post_sha256 = base._canonical_digest(observed_post_state)
        if observed_post_sha256 == baseline_sha256:
            raise CHRTransactionPostApplyVerificationError(
                "successful apply did not change the configuration digest"
            )

        lifecycle = transition_transaction_lifecycle(
            lifecycle=lifecycle,
            to_phase="apply_observed",
            evidence={
                "evidence_ref": "runtime-evidence/disposable-chr/successful-apply",
                "exact_plan_revalidated": True,
                "exact_pre_state_revalidated": True,
                "backup_revalidated": True,
                "management_path_revalidated": True,
                "connectivity_revalidated": True,
                "apply_completed": True,
            },
        ).as_dict()

        # Independent verification starts here. Do not reuse the mutation
        # helper or its object observations as verification evidence.
        verifier_admin = base.LoopbackCHRAdmin(admin_url)
        verification_platform = verifier_admin.assert_disposable_chr()
        verified_interfaces = _required_interfaces_running(verifier_admin)
        verified_counts = runtime_rollback._assert_mutated_state(verifier_admin)
        if verified_counts != observed_counts:
            raise CHRTransactionPostApplyVerificationError(
                "fresh post-apply managed-object counts differ from apply observation"
            )
        verified_post_state = chunked._configuration_snapshot_with_pcc(verifier_admin)
        verified_post_sha256 = base._canonical_digest(verified_post_state)
        if verified_post_sha256 != observed_post_sha256:
            raise CHRTransactionPostApplyVerificationError(
                "fresh post-apply digest differs from the applied state digest"
            )

        lifecycle = transition_transaction_lifecycle(
            lifecycle=lifecycle,
            to_phase="verification_pending",
            evidence={
                "evidence_ref": "runtime-evidence/disposable-chr/fresh-post-apply-snapshot",
                "post_state_sha256": verified_post_sha256,
            },
        ).as_dict()
        lifecycle = transition_transaction_lifecycle(
            lifecycle=lifecycle,
            to_phase="verified",
            evidence={
                "evidence_ref": "runtime-evidence/disposable-chr/post-apply-verification",
                "management_ok": True,
                "connectivity_ok": True,
                "intended_state_ok": True,
                "post_state_sha256": verified_post_sha256,
            },
        ).as_dict()
    finally:
        if applied:
            try:
                cleanup_result = runtime_rollback._execute_import(
                    admin,
                    file_name=runtime_rollback.ROLLBACK_FILE,
                    expect_success=True,
                )
                runtime_rollback._assert_managed_state_absent(admin)
                cleanup_state = chunked._configuration_snapshot_with_pcc(admin)
                cleanup_sha256 = base._canonical_digest(cleanup_state)
                cleanup_completed = cleanup_sha256 == baseline_sha256
            except (OSError, base.CHRRenderDryRunError, runtime_rollback.CHRMutationRollbackError):
                cleanup_completed = False
        for name in runtime_rollback.TEMP_FILES:
            base._delete_file_if_present(admin, name)
        base._assert_files_absent(admin, runtime_rollback.TEMP_FILES)

    if not cleanup_completed:
        raise CHRTransactionPostApplyVerificationError(
            "disposable CHR post-apply lab cleanup did not restore the exact baseline"
        )
    if lifecycle.get("phase") != "verified":
        raise CHRTransactionPostApplyVerificationError(
            "post-apply lifecycle did not reach verified"
        )

    return {
        "ok": True,
        "scope": "disposable_chr_transaction_independent_post_apply_verification",
        "workflow_sha": exact_sha,
        "transaction": {
            "transaction_id": envelope["transaction_id"],
            "envelope_sha256": envelope["envelope_sha256"],
            "render_sha256": plan["render_sha256"],
            "pre_state_sha256": baseline_sha256,
            "command_count": len(commands),
        },
        "admission": adapter_admission,
        "lifecycle": lifecycle,
        "apply": apply_result,
        "rollback_preflight": rollback_preflight,
        "post_apply_verification": {
            "fresh_rest_session": True,
            "apply_observation_reused_for_verification_state": False,
            "management_rest_ok": True,
            "required_interfaces_running": True,
            "required_interfaces": verified_interfaces,
            "intended_state_ok": True,
            "managed_object_counts": verified_counts,
            "post_state_sha256": verified_post_sha256,
            "apply_observed_state_sha256": observed_post_sha256,
            "post_state_matches_apply_observation": verified_post_sha256
            == observed_post_sha256,
            "platform": {
                "version": str(verification_platform.get("version") or ""),
                "architecture": str(verification_platform.get("architecture-name") or ""),
                "board_name": str(verification_platform.get("board-name") or ""),
            },
            "connectivity_scope": "required_interfaces_running_only",
            "routed_data_plane_claimed": False,
            "raw_configuration_recorded": False,
            "secret_values_present": False,
        },
        "lab_cleanup": {
            "completed": cleanup_completed,
            "cleanup_import": cleanup_result,
            "cleanup_state_sha256": cleanup_sha256,
            "baseline_sha256": baseline_sha256,
            "baseline_digest_restored": cleanup_sha256 == baseline_sha256,
            "changes_transaction_lifecycle": False,
        },
        "post_apply_verification_claimed": True,
        "management_survival_after_apply_claimed": True,
        "management_survival_during_apply_claimed": False,
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
        description="Prove independent post-apply verification on disposable CHR"
    )
    parser.add_argument("--admin-url", default="http://127.0.0.1:9580")
    parser.add_argument("--workflow-sha", required=True)
    parser.add_argument("--output", required=True)
    args = parser.parse_args()

    output = Path(args.output)
    output.parent.mkdir(parents=True, exist_ok=True)
    try:
        result = verify_transaction_post_apply(
            admin_url=args.admin_url,
            workflow_sha=args.workflow_sha,
        )
        rc = 0
    except (
        OSError,
        CHRTransactionPostApplyVerificationError,
        TransactionAdapterAdmissionError,
        TransactionBackupEvidenceError,
        TransactionEnvelopeError,
        TransactionLifecycleError,
        base.CHRRenderDryRunError,
        runtime_rollback.CHRMutationRollbackError,
    ) as exc:
        result = {
            "ok": False,
            "error": str(exc),
            "scope": "disposable_chr_transaction_independent_post_apply_verification",
            "post_apply_verification_claimed": False,
            "management_survival_after_apply_claimed": False,
            "management_survival_during_apply_claimed": False,
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
        rc = 18

    output.write_text(
        json.dumps(result, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    print(json.dumps(result, indent=2, sort_keys=True))
    return rc


if __name__ == "__main__":
    raise SystemExit(main())
