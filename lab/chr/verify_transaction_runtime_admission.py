from __future__ import annotations

import argparse
import hashlib
import json
import re
from pathlib import Path
from typing import Any, Mapping

import build_renderer_syntax_fixture as fixture_builder
import verify_mutation_rollback as runtime_rollback
import verify_render_dry_run as base
import verify_render_dry_run_chunked as chunked

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


class CHRTransactionRuntimeAdmissionError(RuntimeError):
    pass


_GIT_SHA = re.compile(r"^[0-9a-f]{40}$")
_REQUIRED_INTERFACES = {"ether1", "ether2", "ether3"}


def _canonical_sha256(value: Any) -> str:
    encoded = json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        default=str,
    ).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def _workflow_sha(value: str) -> str:
    normalized = str(value or "").strip().lower()
    if not _GIT_SHA.fullmatch(normalized):
        raise CHRTransactionRuntimeAdmissionError(
            "workflow SHA must be an exact lowercase 40-character Git commit SHA"
        )
    return normalized


def _required_interfaces(admin: base.LoopbackCHRAdmin) -> list[str]:
    _, payload = admin.request("GET", "interface")
    names = {
        str(row.get("name") or "")
        for row in base._rows(payload)
        if isinstance(row, Mapping)
    }
    missing = sorted(_REQUIRED_INTERFACES - names)
    if missing:
        raise CHRTransactionRuntimeAdmissionError(
            f"disposable CHR transaction fixture is missing interfaces: {missing}"
        )
    return sorted(_REQUIRED_INTERFACES)


def _render_plan(fixture: Mapping[str, Any]) -> dict[str, Any]:
    commands = fixture.get("commands")
    if not isinstance(commands, list) or len(commands) != 38:
        raise CHRTransactionRuntimeAdmissionError(
            "transaction runtime admission requires the accepted 38-command CHR fixture"
        )
    normalized_commands: list[dict[str, Any]] = []
    for command in commands:
        if not isinstance(command, Mapping):
            raise CHRTransactionRuntimeAdmissionError(
                "transaction runtime fixture contains a non-object command"
            )
        normalized_commands.append(dict(command))
    plan = {
        "schema_version": "routeros-render-plan/1",
        "commands": normalized_commands,
        "blocked_operations": [],
        "transport_present": False,
        "apply_available": False,
        "write_authorized": False,
    }
    plan["render_sha256"] = _canonical_sha256(plan)
    return plan


def _sanitized_pre_state_artifact(
    *,
    workflow_sha: str,
    platform: Mapping[str, Any],
    baseline_sha256: str,
    interface_names: list[str],
) -> dict[str, Any]:
    return {
        "schema_version": "routeros-sanitized-pre-state-evidence/1",
        "scope": "normalized_digest_only",
        "workflow_sha": workflow_sha,
        "configuration_sha256": baseline_sha256,
        "platform": {
            "version": str(platform.get("version") or ""),
            "architecture": str(platform.get("architecture-name") or ""),
            "board_name": str(platform.get("board-name") or ""),
        },
        "required_interfaces": list(interface_names),
        "raw_configuration_present": False,
        "binary_backup_present": False,
        "secret_values_present": False,
    }


def verify_transaction_runtime_admission(
    *,
    admin_url: str,
    workflow_sha: str,
) -> dict[str, Any]:
    """Admit one exact transaction before invoking the proven CHR mutation lab.

    This path is deliberately lab-only. The product still has no writer or
    transport. The function proves that the transaction envelope, lifecycle and
    disposable-CHR admission boundary are all satisfied before the existing
    mutation/failure/rollback runtime is called.
    """

    exact_sha = _workflow_sha(workflow_sha)
    admin = base.LoopbackCHRAdmin(admin_url)
    platform = admin.assert_disposable_chr()
    interface_names = _required_interfaces(admin)

    fixture = fixture_builder.build_syntax_fixture()
    plan = _render_plan(fixture)
    baseline = chunked._configuration_snapshot_with_pcc(admin)
    baseline_sha256 = base._canonical_digest(baseline)

    sanitized_pre_state = _sanitized_pre_state_artifact(
        workflow_sha=exact_sha,
        platform=platform,
        baseline_sha256=baseline_sha256,
        interface_names=interface_names,
    )
    backup = build_transaction_backup_evidence(
        kind="sanitized_export",
        artifact_ref=(
            f"artifact://chr/{exact_sha}/transaction-pre-state-digest.json"
        ),
        sha256=_canonical_sha256(sanitized_pre_state),
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

    admission = admit_disposable_chr_candidate(
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
    if admission.get("target_kind") != "disposable_chr":
        raise CHRTransactionRuntimeAdmissionError(
            "transaction admission did not produce a disposable CHR candidate"
        )

    # Revalidate the lab management/connectivity surface immediately before the
    # existing runtime is invoked. The following call is the first mutation-capable
    # operation in this transaction wrapper, and it occurs only after admission.
    _required_interfaces(admin)
    runtime = runtime_rollback.verify_mutation_rollback(admin_url=admin_url)

    if runtime.get("acceptance") != "PASS" or runtime.get("ok") is not True:
        raise CHRTransactionRuntimeAdmissionError(
            "admitted CHR runtime did not complete the existing rollback acceptance"
        )
    if runtime.get("production_writer_available") is not False:
        raise CHRTransactionRuntimeAdmissionError(
            "admitted CHR runtime unexpectedly exposed a production writer"
        )
    if runtime.get("write_authorized") is not False:
        raise CHRTransactionRuntimeAdmissionError(
            "admitted CHR runtime unexpectedly authorized production writes"
        )
    if runtime.get("configuration_baseline_sha256") != baseline_sha256:
        raise CHRTransactionRuntimeAdmissionError(
            "runtime baseline does not match the pre-admission transaction envelope"
        )

    apply = runtime.get("apply")
    if not isinstance(apply, Mapping) or apply.get("verdict") != "OK":
        raise CHRTransactionRuntimeAdmissionError(
            "runtime apply observation is missing after admission"
        )
    lifecycle = transition_transaction_lifecycle(
        lifecycle=lifecycle,
        to_phase="apply_observed",
        evidence={
            "evidence_ref": "runtime-evidence/disposable-chr/apply-observation",
            "exact_plan_revalidated": True,
            "exact_pre_state_revalidated": True,
            "backup_revalidated": True,
            "management_path_revalidated": True,
            "connectivity_revalidated": True,
            "apply_completed": True,
        },
    ).as_dict()

    if runtime.get("failure_observed") is not True:
        raise CHRTransactionRuntimeAdmissionError(
            "runtime failure injection was not observed"
        )
    lifecycle = transition_transaction_lifecycle(
        lifecycle=lifecycle,
        to_phase="rollback_required",
        evidence={
            "evidence_ref": "runtime-evidence/disposable-chr/failure-observation",
            "failure_observed": True,
            "failure_reason_ref": "finding/disposable-chr-controlled-failure",
        },
    ).as_dict()

    rollback = runtime.get("rollback")
    rollback_sha256 = str(runtime.get("configuration_rollback_sha256") or "")
    if not isinstance(rollback, Mapping) or rollback.get("verdict") != "OK":
        raise CHRTransactionRuntimeAdmissionError(
            "runtime rollback observation is missing"
        )
    lifecycle = transition_transaction_lifecycle(
        lifecycle=lifecycle,
        to_phase="rollback_observed",
        evidence={
            "evidence_ref": "runtime-evidence/disposable-chr/rollback-observation",
            "rollback_completed": True,
            "rollback_state_sha256": rollback_sha256,
        },
    ).as_dict()

    return {
        "ok": True,
        "scope": "disposable_chr_transaction_runtime_admission",
        "workflow_sha": exact_sha,
        "platform": sanitized_pre_state["platform"],
        "sanitized_pre_state": sanitized_pre_state,
        "backup_evidence": backup,
        "transaction": {
            "transaction_id": envelope["transaction_id"],
            "envelope_sha256": envelope["envelope_sha256"],
            "render_sha256": plan["render_sha256"],
            "pre_state_sha256": baseline_sha256,
            "command_count": len(plan["commands"]),
        },
        "admission": admission,
        "lifecycle": lifecycle,
        "runtime": runtime,
        "admission_completed_before_runtime_call": True,
        "runtime_baseline_matches_envelope": True,
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
        description="Prove transaction admission before disposable CHR mutation runtime"
    )
    parser.add_argument("--admin-url", default="http://127.0.0.1:9380")
    parser.add_argument("--workflow-sha", required=True)
    parser.add_argument("--output", required=True)
    args = parser.parse_args()

    output = Path(args.output)
    output.parent.mkdir(parents=True, exist_ok=True)
    try:
        result = verify_transaction_runtime_admission(
            admin_url=args.admin_url,
            workflow_sha=args.workflow_sha,
        )
        rc = 0
    except (
        OSError,
        CHRTransactionRuntimeAdmissionError,
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
            "recovery_verification_claimed": False,
            "operator_attestation_claimed": False,
            "production_writer_available": False,
            "transport_exposed_to_product": False,
            "physical_router_targeted": False,
            "production_allowed": False,
            "write_authorized": False,
            "acceptance": "FAIL",
        }
        rc = 16

    output.write_text(
        json.dumps(result, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    print(json.dumps(result, indent=2, sort_keys=True))
    return rc


if __name__ == "__main__":
    raise SystemExit(main())
