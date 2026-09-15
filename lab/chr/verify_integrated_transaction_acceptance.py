from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any, Mapping

import build_renderer_syntax_fixture as fixture_builder
import verify_mutation_rollback as runtime_rollback
import verify_render_dry_run as base
import verify_render_dry_run_chunked as chunked
import verify_transaction_backup_acceptance as real_backup
import verify_transaction_management_survival as management
import verify_transaction_post_apply as post_apply
import verify_transaction_runtime_admission as admission_helpers

from router_configuration.transaction_adapter_admission import (
    TransactionAdapterAdmissionError,
    admit_disposable_chr_candidate,
)
from router_configuration.transaction_backup_evidence import (
    TransactionBackupEvidenceError,
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


class CHRIntegratedTransactionAcceptanceError(RuntimeError):
    pass


def _post_apply_checks(
    *,
    admin_url: str,
    commands: list[Mapping[str, Any]],
    expected_post_sha256: str,
) -> dict[str, Any]:
    """Independently verify applicable WAN/DNS/routing state after apply."""

    admin = base.LoopbackCHRAdmin(admin_url)
    platform = admin.assert_disposable_chr()
    interfaces = post_apply._required_interfaces_running(admin)
    counts = runtime_rollback._assert_mutated_state(admin)
    post_state = chunked._configuration_snapshot_with_pcc(admin)
    post_state_sha256 = base._canonical_digest(post_state)
    if post_state_sha256 != expected_post_sha256:
        raise CHRIntegratedTransactionAcceptanceError(
            "fresh post-apply digest differs from the apply observation"
        )

    dns_commands = [
        str(item.get("command") or "")
        for item in commands
        if str(item.get("command") or "").lstrip().startswith("/ip/dns")
    ]
    dns_applicable = bool(dns_commands)
    dns_surface_readable = True
    if dns_applicable:
        status, payload = admin.request("GET", "ip/dns")
        dns_surface_readable = status < 400 and isinstance(payload, (Mapping, list))
        if not dns_surface_readable:
            raise CHRIntegratedTransactionAcceptanceError(
                "DNS verification was applicable but the RouterOS DNS surface was not readable"
            )

    wan_ok = (
        counts.get("wan_addresses") == 2
        and counts.get("routing_tables") == 2
        and set(interfaces) == {"ether1", "ether2", "ether3"}
    )
    routing_ok = (
        counts.get("recursive_probe_routes") == 4
        and counts.get("recursive_default_routes") == 4
        and counts.get("pcc_policy_routes") == 8
    )
    if not wan_ok or not routing_ok:
        raise CHRIntegratedTransactionAcceptanceError(
            "post-apply WAN/routing verification did not match the accepted fixture"
        )

    return {
        "fresh_rest_session": True,
        "apply_observation_reused_for_verification_state": False,
        "management_rest_ok": True,
        "required_interfaces_running": True,
        "required_interfaces": interfaces,
        "intended_state_ok": True,
        "managed_object_counts": counts,
        "post_state_sha256": post_state_sha256,
        "wan": {
            "applicable": True,
            "passed": wan_ok,
            "wan_address_count": counts.get("wan_addresses"),
            "routing_table_count": counts.get("routing_tables"),
        },
        "routing": {
            "applicable": True,
            "passed": routing_ok,
            "recursive_probe_route_count": counts.get("recursive_probe_routes"),
            "recursive_default_route_count": counts.get("recursive_default_routes"),
            "pcc_policy_route_count": counts.get("pcc_policy_routes"),
        },
        "dns": {
            "applicable": dns_applicable,
            "passed": dns_surface_readable,
            "plan_contains_dns_mutation": dns_applicable,
            "not_applicable_reason": None
            if dns_applicable
            else "accepted 38-command transaction contains no /ip/dns mutation",
        },
        "all_applicable_checks_passed": True,
        "platform": {
            "version": str(platform.get("version") or ""),
            "architecture": str(platform.get("architecture-name") or ""),
            "board_name": str(platform.get("board-name") or ""),
        },
        "routed_data_plane_claimed": False,
        "raw_configuration_recorded": False,
        "secret_values_present": False,
    }


def verify_integrated_transaction_acceptance(
    *,
    admin_url: str,
    ssh_port: int,
    workflow_sha: str,
    export_output: Path,
) -> dict[str, Any]:
    """Prove one disposable-CHR transaction from real backup through recovery.

    The same transaction binding covers:
    real dual pre-change backup, admission, management survival during apply,
    fresh post-apply WAN/routing verification, an intentionally induced failure,
    rollback, and independent recovery verification. The accepted fixture has no
    DNS mutation, so DNS is explicitly recorded as not applicable instead of
    being falsely claimed.

    This is a disposable-CHR acceptance harness only. It does not expose a
    product transport, production writer, physical-router target or write
    authorization.
    """

    exact_sha = admission_helpers._workflow_sha(workflow_sha)
    admin = base.LoopbackCHRAdmin(admin_url)
    platform = admin.assert_disposable_chr()
    interface_names = admission_helpers._required_interfaces(admin)

    fixture = fixture_builder.build_syntax_fixture()
    plan = admission_helpers._render_plan(fixture)
    commands = plan["commands"]
    if len(commands) != 38:
        raise CHRIntegratedTransactionAcceptanceError(
            f"integrated gate requires 38 commands, observed {len(commands)}"
        )

    baseline = chunked._configuration_snapshot_with_pcc(admin)
    baseline_sha256 = base._canonical_digest(baseline)

    backup_acceptance = real_backup.verify_transaction_backup_acceptance(
        admin_url=admin_url,
        ssh_port=ssh_port,
        workflow_sha=exact_sha,
        export_output=export_output,
    )
    if backup_acceptance.get("acceptance") != "PASS" or backup_acceptance.get("ok") is not True:
        raise CHRIntegratedTransactionAcceptanceError(
            "real dual pre-change backup acceptance did not pass"
        )
    if backup_acceptance.get("pre_state_sha256") != baseline_sha256:
        raise CHRIntegratedTransactionAcceptanceError(
            "real dual backup is not bound to the integrated transaction pre-state"
        )
    backup_set = backup_acceptance.get("backup_set")
    capture_proof = backup_acceptance.get("capture_proof")
    if not isinstance(backup_set, Mapping) or backup_set.get(
        "production_backup_requirements_satisfied"
    ) is not True:
        raise CHRIntegratedTransactionAcceptanceError(
            "real dual backup does not satisfy the production backup evidence contract"
        )
    if not isinstance(capture_proof, Mapping):
        raise CHRIntegratedTransactionAcceptanceError(
            "real dual backup capture proof is missing"
        )
    required_backup_proof = {
        "protected_binary_sha256_from_downloaded_bytes": True,
        "router_binary_removed": True,
        "runner_binary_removed": True,
        "temporary_fetch_user_removed": True,
        "router_export_removed_after_capture": True,
    }
    for key, expected in required_backup_proof.items():
        if capture_proof.get(key) is not expected:
            raise CHRIntegratedTransactionAcceptanceError(
                f"real dual backup proof failed: {key}"
            )
    if int(capture_proof.get("protected_binary_bytes") or 0) < 128:
        raise CHRIntegratedTransactionAcceptanceError(
            "protected binary backup is unexpectedly small"
        )
    if capture_proof.get("protected_binary_encryption_requested") != "aes-sha256":
        raise CHRIntegratedTransactionAcceptanceError(
            "protected binary backup did not request aes-sha256 encryption"
        )
    if capture_proof.get("backup_password_persisted") is not False:
        raise CHRIntegratedTransactionAcceptanceError(
            "backup credential persistence was detected"
        )
    if capture_proof.get("fetch_password_persisted") is not False:
        raise CHRIntegratedTransactionAcceptanceError(
            "fetch credential persistence was detected"
        )

    sanitized_backup = backup_acceptance.get("sanitized_export")
    if not isinstance(sanitized_backup, Mapping):
        raise CHRIntegratedTransactionAcceptanceError(
            "sanitized backup evidence is missing"
        )
    validate_transaction_backup_evidence(
        sanitized_backup,
        expected_pre_state_sha256=baseline_sha256,
    )

    envelope = build_transaction_envelope(
        render_plan=plan,
        pre_state_sha256=baseline_sha256,
        backup=sanitized_backup,
        approval={
            "approved": True,
            "plan_sha256": plan["render_sha256"],
            "approver_ref": f"lab-policy/disposable-chr/{exact_sha}",
        },
        management_path={
            "ok": True,
            "evidence_ref": "runtime-evidence/disposable-chr/integrated-rest-management",
        },
        connectivity_baseline={
            "ok": True,
            "evidence_ref": "runtime-evidence/disposable-chr/integrated-interface-baseline",
        },
    ).as_dict()
    lifecycle = initialize_transaction_lifecycle(envelope=envelope).as_dict()
    lifecycle = transition_transaction_lifecycle(
        lifecycle=lifecycle,
        to_phase="authorized",
        evidence={
            "evidence_ref": "runtime-evidence/disposable-chr/integrated-lab-authorization",
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
        raise CHRIntegratedTransactionAcceptanceError(
            "integrated gate did not admit a disposable CHR candidate"
        )

    rollback_script = runtime_rollback._rollback_script()
    apply_script = management._instrumented_apply_script(commands)
    observer = management._ManagementObserver(admin_url)
    observer_started = False
    mutation_started = False
    rollback_preflight: dict[str, Any] | None = None
    apply_result: dict[str, Any] | None = None
    failure_result: dict[str, Any] | None = None
    rollback_result: dict[str, Any] | None = None
    management_summary: dict[str, Any] | None = None
    post_apply_verification: dict[str, Any] | None = None
    post_state_sha256: str | None = None
    rollback_state_sha256: str | None = None
    recovery: dict[str, Any] | None = None

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

        # Revalidate the exact pre-state after backup capture and immediately
        # before the first mutation-capable operation.
        pre_apply_state = chunked._configuration_snapshot_with_pcc(admin)
        if base._canonical_digest(pre_apply_state) != baseline_sha256:
            raise CHRIntegratedTransactionAcceptanceError(
                "pre-state changed after backup capture and before apply"
            )
        admission_helpers._required_interfaces(admin)

        chunked._create_text_file_chunk_verified(
            admin,
            runtime_rollback.APPLY_FILE,
            apply_script,
        )
        observer.start()
        observer_started = True
        observer.wait_for_successes("pre_apply", management._MIN_PRE_PROBES)
        observer.begin_apply()
        mutation_started = True
        try:
            apply_result = runtime_rollback._execute_import(
                admin,
                file_name=runtime_rollback.APPLY_FILE,
                expect_success=True,
            )
        finally:
            observer.end_apply()
        if apply_result.get("verdict") != "OK":
            raise CHRIntegratedTransactionAcceptanceError(
                "integrated transaction apply did not complete successfully"
            )

        observer.wait_for_successes("post_apply", management._MIN_POST_PROBES)
        observer.stop()
        observer_started = False
        management_summary = management._summarize_management_samples(
            observer.samples()
        )

        runtime_rollback._assert_mutated_state(admin)
        observed_post_state = chunked._configuration_snapshot_with_pcc(admin)
        post_state_sha256 = base._canonical_digest(observed_post_state)
        if post_state_sha256 == baseline_sha256:
            raise CHRIntegratedTransactionAcceptanceError(
                "integrated apply did not change the configuration digest"
            )

        lifecycle = transition_transaction_lifecycle(
            lifecycle=lifecycle,
            to_phase="apply_observed",
            evidence={
                "evidence_ref": "runtime-evidence/disposable-chr/integrated-apply",
                "exact_plan_revalidated": True,
                "exact_pre_state_revalidated": True,
                "backup_revalidated": True,
                "management_path_revalidated": True,
                "connectivity_revalidated": True,
                "apply_completed": True,
            },
        ).as_dict()

        post_apply_verification = _post_apply_checks(
            admin_url=admin_url,
            commands=commands,
            expected_post_sha256=post_state_sha256,
        )
        lifecycle = transition_transaction_lifecycle(
            lifecycle=lifecycle,
            to_phase="verification_pending",
            evidence={
                "evidence_ref": "runtime-evidence/disposable-chr/integrated-post-apply",
                "post_state_sha256": post_state_sha256,
            },
        ).as_dict()

        # Deliberately fail before the transaction can be committed as verified.
        # This keeps post-apply checks and rollback/recovery in one lifecycle.
        chunked._create_text_file_chunk_verified(
            admin,
            runtime_rollback.FAIL_FILE,
            "this\n",
        )
        failure_result = runtime_rollback._execute_import(
            admin,
            file_name=runtime_rollback.FAIL_FILE,
            expect_success=False,
        )
        if failure_result.get("verdict") != "ERROR":
            raise CHRIntegratedTransactionAcceptanceError(
                "integrated transaction failure injection was not observed"
            )
        lifecycle = transition_transaction_lifecycle(
            lifecycle=lifecycle,
            to_phase="rollback_required",
            evidence={
                "evidence_ref": "runtime-evidence/disposable-chr/integrated-induced-failure",
                "failure_observed": True,
                "failure_reason_ref": "finding/disposable-chr/integrated-controlled-failure",
            },
        ).as_dict()

        rollback_result = runtime_rollback._execute_import(
            admin,
            file_name=runtime_rollback.ROLLBACK_FILE,
            expect_success=True,
        )
        if rollback_result.get("verdict") != "OK":
            raise CHRIntegratedTransactionAcceptanceError(
                "integrated rollback import did not complete successfully"
            )
        runtime_rollback._assert_managed_state_absent(admin)
        rollback_state = chunked._configuration_snapshot_with_pcc(admin)
        rollback_state_sha256 = base._canonical_digest(rollback_state)
        if rollback_state_sha256 != baseline_sha256:
            raise CHRIntegratedTransactionAcceptanceError(
                "integrated rollback did not restore the exact transaction pre-state"
            )
        lifecycle = transition_transaction_lifecycle(
            lifecycle=lifecycle,
            to_phase="rollback_observed",
            evidence={
                "evidence_ref": "runtime-evidence/disposable-chr/integrated-rollback",
                "rollback_completed": True,
                "rollback_state_sha256": rollback_state_sha256,
            },
        ).as_dict()

        # Independent recovery proof uses a fresh REST helper after rollback.
        recovery_admin = base.LoopbackCHRAdmin(admin_url)
        recovery_platform = recovery_admin.assert_disposable_chr()
        recovered_interfaces = post_apply._required_interfaces_running(recovery_admin)
        runtime_rollback._assert_managed_state_absent(recovery_admin)
        recovered_state = chunked._configuration_snapshot_with_pcc(recovery_admin)
        recovered_sha256 = base._canonical_digest(recovered_state)
        if recovered_sha256 != baseline_sha256:
            raise CHRIntegratedTransactionAcceptanceError(
                "fresh recovery digest does not match the transaction pre-state"
            )
        recovery = {
            "fresh_rest_session": True,
            "management_rest_recovered": True,
            "required_interfaces_running": True,
            "required_interfaces": recovered_interfaces,
            "managed_objects_reconciled": True,
            "rollback_state_sha256": recovered_sha256,
            "pre_state_sha256": baseline_sha256,
            "rollback_digest_matches_pre_state": True,
            "platform": {
                "version": str(recovery_platform.get("version") or ""),
                "architecture": str(recovery_platform.get("architecture-name") or ""),
                "board_name": str(recovery_platform.get("board-name") or ""),
            },
            "raw_configuration_recorded": False,
            "secret_values_present": False,
        }
        lifecycle = transition_transaction_lifecycle(
            lifecycle=lifecycle,
            to_phase="rolled_back",
            evidence={
                "evidence_ref": "runtime-evidence/disposable-chr/integrated-recovery",
                "management_recovered": True,
                "connectivity_recovered": True,
                "managed_objects_reconciled": True,
                "rollback_state_sha256": recovered_sha256,
            },
        ).as_dict()
    finally:
        if observer_started:
            try:
                observer.end_apply()
                observer.stop()
            except management.CHRTransactionManagementSurvivalError:
                pass
        if mutation_started:
            try:
                runtime_rollback._assert_managed_state_absent(admin)
            except runtime_rollback.CHRMutationRollbackError:
                try:
                    chunked._create_text_file_chunk_verified(
                        admin,
                        runtime_rollback.ROLLBACK_FILE,
                        rollback_script,
                    )
                    runtime_rollback._execute_import(
                        admin,
                        file_name=runtime_rollback.ROLLBACK_FILE,
                        expect_success=True,
                    )
                except (OSError, base.CHRRenderDryRunError, runtime_rollback.CHRMutationRollbackError):
                    pass
        for name in runtime_rollback.TEMP_FILES:
            base._delete_file_if_present(admin, name)
        base._assert_files_absent(admin, runtime_rollback.TEMP_FILES)

    if lifecycle.get("phase") != "rolled_back":
        raise CHRIntegratedTransactionAcceptanceError(
            "integrated transaction lifecycle did not reach rolled_back"
        )
    if not isinstance(post_apply_verification, Mapping):
        raise CHRIntegratedTransactionAcceptanceError(
            "integrated post-apply verification evidence is missing"
        )
    if not isinstance(management_summary, Mapping):
        raise CHRIntegratedTransactionAcceptanceError(
            "integrated management-survival evidence is missing"
        )
    if not isinstance(recovery, Mapping):
        raise CHRIntegratedTransactionAcceptanceError(
            "integrated recovery evidence is missing"
        )
    if rollback_state_sha256 != baseline_sha256:
        raise CHRIntegratedTransactionAcceptanceError(
            "integrated final state is not the exact pre-state"
        )

    protected_binary = backup_acceptance.get("protected_binary")
    if not isinstance(protected_binary, Mapping):
        raise CHRIntegratedTransactionAcceptanceError(
            "protected binary backup evidence is missing"
        )

    return {
        "schema_version": "chr-integrated-transaction-acceptance/1",
        "ok": True,
        "acceptance": "PASS",
        "scope": "disposable_chr_single_transaction_backup_apply_verify_failure_rollback_recovery",
        "workflow_sha": exact_sha,
        "platform": {
            "version": str(platform.get("version") or ""),
            "architecture": str(platform.get("architecture-name") or ""),
            "board_name": str(platform.get("board-name") or ""),
        },
        "transaction": {
            "transaction_id": envelope["transaction_id"],
            "envelope_sha256": envelope["envelope_sha256"],
            "render_sha256": plan["render_sha256"],
            "pre_state_sha256": baseline_sha256,
            "post_apply_state_sha256": post_state_sha256,
            "final_state_sha256": rollback_state_sha256,
            "command_count": len(commands),
            "single_transaction_binding": True,
        },
        "real_dual_backup": {
            "pre_state_sha256": backup_acceptance["pre_state_sha256"],
            "sanitized_export_sha256": sanitized_backup["sha256"],
            "protected_binary_sha256": protected_binary["sha256"],
            "protected_binary_bytes": capture_proof["protected_binary_bytes"],
            "protected_binary_sha256_from_downloaded_bytes": capture_proof[
                "protected_binary_sha256_from_downloaded_bytes"
            ],
            "protected_binary_encryption_requested": capture_proof[
                "protected_binary_encryption_requested"
            ],
            "production_backup_requirements_satisfied": backup_set[
                "production_backup_requirements_satisfied"
            ],
            "backup_password_persisted": capture_proof["backup_password_persisted"],
            "fetch_password_persisted": capture_proof["fetch_password_persisted"],
            "router_binary_removed": capture_proof["router_binary_removed"],
            "runner_binary_removed": capture_proof["runner_binary_removed"],
            "temporary_fetch_user_removed": capture_proof["temporary_fetch_user_removed"],
            "raw_binary_payload_present": False,
        },
        "admission": adapter_admission,
        "rollback_preflight": rollback_preflight,
        "apply": apply_result,
        "management_survival": management_summary,
        "post_apply_verification": post_apply_verification,
        "failure_injection": failure_result,
        "rollback": {
            "import": rollback_result,
            "rollback_state_sha256": rollback_state_sha256,
            "baseline_digest_restored": rollback_state_sha256 == baseline_sha256,
            "managed_objects_removed": True,
        },
        "recovery_verification": recovery,
        "lifecycle": lifecycle,
        "post_apply_verification_completed_before_failure": True,
        "management_survival_during_apply_claimed": True,
        "recovery_verification_claimed": True,
        "routed_data_plane_claimed": False,
        "operator_attestation_claimed": False,
        "production_writer_available": False,
        "transport_exposed_to_product": False,
        "physical_router_targeted": False,
        "production_allowed": False,
        "write_authorized": False,
    }


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Prove one integrated disposable-CHR transaction through recovery"
    )
    parser.add_argument("--admin-url", default="http://127.0.0.1:9880")
    parser.add_argument("--ssh-port", type=int, default=9823)
    parser.add_argument("--workflow-sha", required=True)
    parser.add_argument("--export-output", required=True)
    parser.add_argument("--output", required=True)
    args = parser.parse_args()

    output = Path(args.output)
    output.parent.mkdir(parents=True, exist_ok=True)
    try:
        result = verify_integrated_transaction_acceptance(
            admin_url=args.admin_url,
            ssh_port=args.ssh_port,
            workflow_sha=args.workflow_sha,
            export_output=Path(args.export_output),
        )
        rc = 0
    except (
        OSError,
        CHRIntegratedTransactionAcceptanceError,
        TransactionAdapterAdmissionError,
        TransactionBackupEvidenceError,
        TransactionEnvelopeError,
        TransactionLifecycleError,
        real_backup.CHRTransactionBackupAcceptanceError,
        management.CHRTransactionManagementSurvivalError,
        post_apply.CHRTransactionPostApplyVerificationError,
        admission_helpers.CHRTransactionRuntimeAdmissionError,
        base.CHRRenderDryRunError,
        runtime_rollback.CHRMutationRollbackError,
    ) as exc:
        result = {
            "schema_version": "chr-integrated-transaction-acceptance/1",
            "ok": False,
            "acceptance": "FAIL",
            "error_class": exc.__class__.__name__,
            "scope": "disposable_chr_single_transaction_backup_apply_verify_failure_rollback_recovery",
            "management_survival_during_apply_claimed": False,
            "recovery_verification_claimed": False,
            "routed_data_plane_claimed": False,
            "operator_attestation_claimed": False,
            "production_writer_available": False,
            "transport_exposed_to_product": False,
            "physical_router_targeted": False,
            "production_allowed": False,
            "write_authorized": False,
        }
        rc = 20

    output.write_text(
        json.dumps(result, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    print(json.dumps(result, indent=2, sort_keys=True))
    return rc


if __name__ == "__main__":
    raise SystemExit(main())
