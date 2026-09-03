from __future__ import annotations

import argparse
import json
import threading
import time
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


class CHRTransactionManagementSurvivalError(RuntimeError):
    pass


_REQUIRED_MANAGEMENT_INTERFACE = "ether1"
_PROBE_INTERVAL_SECONDS = 0.05
_INSTRUMENTATION_DELAY_MS = 75
_MIN_PRE_PROBES = 3
_MIN_DURING_PROBES = 8
_MIN_POST_PROBES = 3


def _is_true(value: Any) -> bool:
    return str(value or "").strip().lower() in {"1", "true", "yes"}


def _management_probe(
    admin: base.LoopbackCHRAdmin,
    *,
    sequence: int,
    phase: str,
) -> dict[str, Any]:
    started = time.monotonic()
    sample: dict[str, Any] = {
        "sequence": sequence,
        "phase": phase,
        "ok": False,
        "resource_ok": False,
        "management_interface_running": False,
        "managed_pcc_mangle_count": 0,
        "error_class": None,
    }
    try:
        resource_status, resource = admin.request("GET", "system/resource")
        interface_status, interface_payload = admin.request("GET", "interface")
        mangle_status, mangle_payload = admin.request("GET", "ip/firewall/mangle")

        resource_ok = (
            resource_status < 400
            and isinstance(resource, Mapping)
            and resource.get("platform") == "MikroTik"
            and str(resource.get("architecture-name") or "") == "x86_64"
            and str(resource.get("board-name") or "").startswith("CHR")
        )
        interfaces = {
            str(row.get("name") or ""): row
            for row in base._rows(interface_payload)
            if isinstance(row, Mapping)
        }
        management_row = interfaces.get(_REQUIRED_MANAGEMENT_INTERFACE)
        management_running = bool(
            interface_status < 400
            and isinstance(management_row, Mapping)
            and _is_true(management_row.get("running"))
            and not _is_true(management_row.get("disabled"))
        )
        managed_mangle = [
            row
            for row in base._rows(mangle_payload)
            if isinstance(row, Mapping)
            and str(row.get("comment") or "").startswith("routercfg:managed:pcc-")
        ]
        sample.update(
            {
                "resource_ok": resource_ok,
                "management_interface_running": management_running,
                "managed_pcc_mangle_count": len(managed_mangle),
                "ok": bool(resource_ok and management_running and mangle_status < 400),
            }
        )
    except (OSError, base.CHRRenderDryRunError) as exc:
        # Keep evidence sanitized: record only the exception class, never the
        # transport error text or a raw RouterOS payload.
        sample["error_class"] = exc.__class__.__name__
    sample["duration_ms"] = round((time.monotonic() - started) * 1000.0, 3)
    return sample


class _ManagementObserver:
    def __init__(self, admin_url: str) -> None:
        self._admin = base.LoopbackCHRAdmin(admin_url)
        self._apply_window = threading.Event()
        self._stop = threading.Event()
        self._samples: list[dict[str, Any]] = []
        self._lock = threading.Lock()
        self._thread = threading.Thread(
            target=self._run,
            name="chr-management-observer",
            daemon=True,
        )

    def start(self) -> None:
        self._thread.start()

    def begin_apply(self) -> None:
        self._apply_window.set()

    def end_apply(self) -> None:
        self._apply_window.clear()

    def stop(self) -> None:
        self._stop.set()
        self._thread.join(timeout=5.0)
        if self._thread.is_alive():
            raise CHRTransactionManagementSurvivalError(
                "management observer did not stop cleanly"
            )

    def samples(self) -> list[dict[str, Any]]:
        with self._lock:
            return [dict(item) for item in self._samples]

    def wait_for_successes(
        self,
        phase: str,
        minimum: int,
        *,
        timeout_seconds: float = 5.0,
    ) -> None:
        deadline = time.monotonic() + timeout_seconds
        while time.monotonic() < deadline:
            successful = sum(
                1
                for item in self.samples()
                if item.get("phase") == phase and item.get("ok") is True
            )
            if successful >= minimum:
                return
            time.sleep(0.02)
        raise CHRTransactionManagementSurvivalError(
            f"management observer did not collect {minimum} successful {phase} probes"
        )

    def _run(self) -> None:
        sequence = 0
        while not self._stop.is_set():
            sequence += 1
            if self._apply_window.is_set():
                phase = "during_apply"
            else:
                with self._lock:
                    has_during = any(
                        item.get("phase") == "during_apply" for item in self._samples
                    )
                phase = "post_apply" if has_during else "pre_apply"
            sample = _management_probe(
                self._admin,
                sequence=sequence,
                phase=phase,
            )
            with self._lock:
                self._samples.append(sample)
            self._stop.wait(_PROBE_INTERVAL_SECONDS)


def _instrumented_apply_script(commands: list[Mapping[str, Any]]) -> str:
    """Add lab-only observation gaps without changing rendered commands.

    The exact rendered RouterOS commands remain byte-for-byte unchanged and in
    their original order. ``:delay`` statements are inserted only by this CHR
    acceptance harness so an independent REST observer can sample while the
    mutation import is actually progressing. This is not a production timing or
    latency claim.
    """

    lines = [f":delay {_INSTRUMENTATION_DELAY_MS}ms"]
    for item in commands:
        command = str(item["command"])
        lines.append(command)
        lines.append(f":delay {_INSTRUMENTATION_DELAY_MS}ms")
    return "\n".join(lines) + "\n"


def _summarize_management_samples(samples: list[dict[str, Any]]) -> dict[str, Any]:
    if not samples:
        raise CHRTransactionManagementSurvivalError(
            "management observer produced no samples"
        )

    phase_counts: dict[str, int] = {}
    phase_success_counts: dict[str, int] = {}
    for phase in ("pre_apply", "during_apply", "post_apply"):
        phase_rows = [item for item in samples if item.get("phase") == phase]
        phase_counts[phase] = len(phase_rows)
        phase_success_counts[phase] = sum(
            1 for item in phase_rows if item.get("ok") is True
        )

    failures = [item for item in samples if item.get("ok") is not True]
    during_rows = [item for item in samples if item.get("phase") == "during_apply"]
    mutation_visible = any(
        int(item.get("managed_pcc_mangle_count") or 0) > 0
        for item in during_rows
        if item.get("ok") is True
    )
    management_running_all = all(
        item.get("management_interface_running") is True for item in samples
    )

    if phase_success_counts["pre_apply"] < _MIN_PRE_PROBES:
        raise CHRTransactionManagementSurvivalError(
            "insufficient successful pre-apply management probes"
        )
    if phase_success_counts["during_apply"] < _MIN_DURING_PROBES:
        raise CHRTransactionManagementSurvivalError(
            "insufficient successful during-apply management probes"
        )
    if phase_success_counts["post_apply"] < _MIN_POST_PROBES:
        raise CHRTransactionManagementSurvivalError(
            "insufficient successful post-apply management probes"
        )
    if failures:
        raise CHRTransactionManagementSurvivalError(
            f"management observer recorded {len(failures)} failed probes"
        )
    if not mutation_visible:
        raise CHRTransactionManagementSurvivalError(
            "management observer did not see managed mutation state during apply"
        )
    if not management_running_all:
        raise CHRTransactionManagementSurvivalError(
            "management interface was not continuously running across observed probes"
        )

    return {
        "independent_rest_session": True,
        "probe_interval_seconds": _PROBE_INTERVAL_SECONDS,
        "sample_count": len(samples),
        "success_count": len(samples) - len(failures),
        "failure_count": len(failures),
        "phase_counts": phase_counts,
        "phase_success_counts": phase_success_counts,
        "minimum_required_successes": {
            "pre_apply": _MIN_PRE_PROBES,
            "during_apply": _MIN_DURING_PROBES,
            "post_apply": _MIN_POST_PROBES,
        },
        "mutation_visible_during_apply": mutation_visible,
        "management_interface": _REQUIRED_MANAGEMENT_INTERFACE,
        "management_interface_running_all_probes": management_running_all,
        "all_probes_successful": not failures,
        "raw_routeros_payload_recorded": False,
        "secret_values_present": False,
        "samples": samples,
    }


def verify_transaction_management_survival(
    *,
    admin_url: str,
    workflow_sha: str,
) -> dict[str, Any]:
    """Prove management REST survival throughout an admitted CHR apply window."""

    exact_sha = admission_helpers._workflow_sha(workflow_sha)
    admin = base.LoopbackCHRAdmin(admin_url)
    platform = admin.assert_disposable_chr()
    interface_names = admission_helpers._required_interfaces(admin)

    fixture = fixture_builder.build_syntax_fixture()
    plan = admission_helpers._render_plan(fixture)
    commands = plan["commands"]
    if len(commands) != 38:
        raise CHRTransactionManagementSurvivalError(
            f"management-survival gate requires the accepted 38-command plan, observed {len(commands)}"
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
        raise CHRTransactionManagementSurvivalError(
            "management-survival gate did not admit a disposable CHR candidate"
        )

    apply_script = _instrumented_apply_script(commands)
    rollback_script = runtime_rollback._rollback_script()
    observer = _ManagementObserver(admin_url)
    observer_started = False
    apply_invoked = False
    apply_result: dict[str, Any] | None = None
    rollback_preflight: dict[str, Any] | None = None
    managed_counts: dict[str, int] | None = None
    post_state_sha256: str | None = None
    management_summary: dict[str, Any] | None = None
    cleanup_result: dict[str, Any] | None = None
    cleanup_sha256: str | None = None
    cleanup_completed = False

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
        admission_helpers._required_interfaces(admin)

        chunked._create_text_file_chunk_verified(
            admin,
            runtime_rollback.APPLY_FILE,
            apply_script,
        )

        observer.start()
        observer_started = True
        observer.wait_for_successes("pre_apply", _MIN_PRE_PROBES)
        observer.begin_apply()
        apply_invoked = True
        try:
            apply_result = runtime_rollback._execute_import(
                admin,
                file_name=runtime_rollback.APPLY_FILE,
                expect_success=True,
            )
        finally:
            observer.end_apply()
        if apply_result.get("verdict") != "OK":
            raise CHRTransactionManagementSurvivalError(
                "admitted transaction apply was not observed as successful"
            )

        observer.wait_for_successes("post_apply", _MIN_POST_PROBES)
        observer.stop()
        observer_started = False
        management_summary = _summarize_management_samples(observer.samples())

        managed_counts = runtime_rollback._assert_mutated_state(admin)
        post_state = chunked._configuration_snapshot_with_pcc(admin)
        post_state_sha256 = base._canonical_digest(post_state)
        if post_state_sha256 == baseline_sha256:
            raise CHRTransactionManagementSurvivalError(
                "management-survival apply did not change the configuration digest"
            )

        lifecycle = transition_transaction_lifecycle(
            lifecycle=lifecycle,
            to_phase="apply_observed",
            evidence={
                "evidence_ref": "runtime-evidence/disposable-chr/management-survived-apply",
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
                "evidence_ref": "runtime-evidence/disposable-chr/management-observer-post-state",
                "post_state_sha256": post_state_sha256,
            },
        ).as_dict()
        lifecycle = transition_transaction_lifecycle(
            lifecycle=lifecycle,
            to_phase="verified",
            evidence={
                "evidence_ref": "runtime-evidence/disposable-chr/continuous-management-verification",
                "management_ok": True,
                "connectivity_ok": True,
                "intended_state_ok": True,
                "post_state_sha256": post_state_sha256,
            },
        ).as_dict()
    finally:
        if observer_started:
            try:
                observer.end_apply()
                observer.stop()
            except CHRTransactionManagementSurvivalError:
                pass
        if apply_invoked:
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

    if management_summary is None:
        raise CHRTransactionManagementSurvivalError(
            "management-survival evidence was not completed"
        )
    if not cleanup_completed:
        raise CHRTransactionManagementSurvivalError(
            "management-survival lab cleanup did not restore the exact baseline"
        )
    if lifecycle.get("phase") != "verified":
        raise CHRTransactionManagementSurvivalError(
            "management-survival lifecycle did not reach verified"
        )

    return {
        "ok": True,
        "scope": "disposable_chr_transaction_management_survival_during_apply",
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
            "command_count": len(commands),
        },
        "instrumentation": {
            "lab_only": True,
            "delay_ms_between_rendered_commands": _INSTRUMENTATION_DELAY_MS,
            "rendered_command_count": len(commands),
            "rendered_commands_modified": False,
            "rendered_command_order_modified": False,
            "production_timing_claimed": False,
        },
        "admission": adapter_admission,
        "lifecycle": lifecycle,
        "rollback_preflight": rollback_preflight,
        "apply": apply_result,
        "managed_object_counts": managed_counts,
        "post_state_sha256": post_state_sha256,
        "management_survival": management_summary,
        "lab_cleanup": {
            "completed": cleanup_completed,
            "cleanup_import": cleanup_result,
            "cleanup_state_sha256": cleanup_sha256,
            "baseline_sha256": baseline_sha256,
            "baseline_digest_restored": cleanup_sha256 == baseline_sha256,
            "changes_transaction_lifecycle": False,
        },
        "management_survival_during_apply_claimed": True,
        "management_survival_after_apply_claimed": True,
        "post_apply_verification_claimed": False,
        "routed_data_plane_claimed": False,
        "recovery_verification_claimed": False,
        "operator_attestation_claimed": False,
        "production_timing_claimed": False,
        "production_writer_available": False,
        "transport_exposed_to_product": False,
        "physical_router_targeted": False,
        "production_allowed": False,
        "write_authorized": False,
        "acceptance": "PASS",
    }


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Prove management-path survival during an admitted disposable CHR apply"
    )
    parser.add_argument("--admin-url", default="http://127.0.0.1:9680")
    parser.add_argument("--workflow-sha", required=True)
    parser.add_argument("--output", required=True)
    args = parser.parse_args()

    output = Path(args.output)
    output.parent.mkdir(parents=True, exist_ok=True)
    try:
        result = verify_transaction_management_survival(
            admin_url=args.admin_url,
            workflow_sha=args.workflow_sha,
        )
        rc = 0
    except (
        OSError,
        CHRTransactionManagementSurvivalError,
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
            "scope": "disposable_chr_transaction_management_survival_during_apply",
            "management_survival_during_apply_claimed": False,
            "management_survival_after_apply_claimed": False,
            "post_apply_verification_claimed": False,
            "routed_data_plane_claimed": False,
            "recovery_verification_claimed": False,
            "operator_attestation_claimed": False,
            "production_timing_claimed": False,
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
