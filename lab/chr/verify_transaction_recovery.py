from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any, Mapping

import verify_mutation_rollback as runtime_rollback
import verify_render_dry_run as base
import verify_render_dry_run_chunked as chunked
import verify_transaction_runtime_admission as admission

from router_configuration.transaction_lifecycle import (
    TransactionLifecycleError,
    transition_transaction_lifecycle,
)


class CHRTransactionRecoveryError(RuntimeError):
    pass


def _require_mapping(value: Any, label: str) -> Mapping[str, Any]:
    if not isinstance(value, Mapping):
        raise CHRTransactionRecoveryError(f"{label} must be an object")
    return value


def verify_transaction_recovery(*, admin_url: str, workflow_sha: str) -> dict[str, Any]:
    """Independently verify recovery after the admitted disposable-CHR runtime.

    The admission verifier deliberately stops at ``rollback_observed``. This
    verifier creates a fresh read-only admin client after that runtime returns,
    re-reads the management/configuration surface, proves the bound pre-state
    digest is restored, proves owned objects are absent, and only then advances
    the audit lifecycle to ``rolled_back``.

    This remains lab-only evidence. It does not expose a product transport,
    production writer, physical-router target, or write authorization.
    """

    admitted = admission.verify_transaction_runtime_admission(
        admin_url=admin_url,
        workflow_sha=workflow_sha,
    )
    if admitted.get("acceptance") != "PASS" or admitted.get("ok") is not True:
        raise CHRTransactionRecoveryError("transaction runtime admission did not PASS")

    lifecycle = _require_mapping(admitted.get("lifecycle"), "admission.lifecycle")
    if lifecycle.get("phase") != "rollback_observed":
        raise CHRTransactionRecoveryError(
            "recovery verification requires lifecycle phase rollback_observed"
        )

    transaction = _require_mapping(admitted.get("transaction"), "admission.transaction")
    bound_pre_state_sha256 = str(transaction.get("pre_state_sha256") or "")
    if len(bound_pre_state_sha256) != 64:
        raise CHRTransactionRecoveryError("bound pre-state digest is missing")

    runtime = _require_mapping(admitted.get("runtime"), "admission.runtime")
    if runtime.get("rollback_digest_restored") is not True:
        raise CHRTransactionRecoveryError(
            "runtime did not report a restored rollback digest before independent verification"
        )

    # Deliberately create a fresh client after rollback. Recovery claims below
    # come from new reads, not from the mutation runtime's cached observations.
    recovery_admin = base.LoopbackCHRAdmin(admin_url)
    recovery_platform = recovery_admin.assert_disposable_chr()
    recovered_interfaces = admission._required_interfaces(recovery_admin)

    runtime_rollback._assert_managed_state_absent(recovery_admin)
    recovery_snapshot = chunked._configuration_snapshot_with_pcc(recovery_admin)
    recovery_sha256 = base._canonical_digest(recovery_snapshot)
    if recovery_sha256 != bound_pre_state_sha256:
        raise CHRTransactionRecoveryError(
            "independent recovery snapshot does not equal the transaction pre-state digest"
        )

    recovered_lifecycle = transition_transaction_lifecycle(
        lifecycle=lifecycle,
        to_phase="rolled_back",
        evidence={
            "evidence_ref": "runtime-evidence/disposable-chr/independent-recovery-verification",
            "management_recovered": True,
            "connectivity_recovered": True,
            "managed_objects_reconciled": True,
            "rollback_state_sha256": recovery_sha256,
        },
    ).as_dict()
    if recovered_lifecycle.get("phase") != "rolled_back":
        raise CHRTransactionRecoveryError("lifecycle did not advance to rolled_back")

    recovery = {
        "independent_read": True,
        "fresh_admin_client": True,
        "management_recovered": True,
        "connectivity_recovered": True,
        "managed_objects_reconciled": True,
        "rollback_state_sha256": recovery_sha256,
        "pre_state_sha256": bound_pre_state_sha256,
        "pre_state_digest_restored": recovery_sha256 == bound_pre_state_sha256,
        "required_interfaces": recovered_interfaces,
        "platform": {
            "version": str(recovery_platform.get("version") or ""),
            "architecture": str(recovery_platform.get("architecture-name") or ""),
            "board_name": str(recovery_platform.get("board-name") or ""),
        },
    }

    return {
        "ok": True,
        "scope": "disposable_chr_transaction_independent_recovery_verification",
        "workflow_sha": str(admitted.get("workflow_sha") or ""),
        "transaction": dict(transaction),
        "recovery": recovery,
        "lifecycle": recovered_lifecycle,
        "admission_phase_before_recovery": lifecycle.get("phase"),
        "recovery_verification_claimed": True,
        "independent_post_rollback_read": True,
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
        description="Independently verify disposable CHR transaction recovery"
    )
    parser.add_argument("--admin-url", default="http://127.0.0.1:9480")
    parser.add_argument("--workflow-sha", required=True)
    parser.add_argument("--output", required=True)
    args = parser.parse_args()

    output = Path(args.output)
    output.parent.mkdir(parents=True, exist_ok=True)
    try:
        result = verify_transaction_recovery(
            admin_url=args.admin_url,
            workflow_sha=args.workflow_sha,
        )
        rc = 0
    except (
        OSError,
        CHRTransactionRecoveryError,
        admission.CHRTransactionRuntimeAdmissionError,
        runtime_rollback.CHRMutationRollbackError,
        TransactionLifecycleError,
        base.CHRRenderDryRunError,
    ) as exc:
        result = {
            "ok": False,
            "error": str(exc),
            "scope": "disposable_chr_transaction_independent_recovery_verification",
            "recovery_verification_claimed": False,
            "independent_post_rollback_read": False,
            "operator_attestation_claimed": False,
            "production_writer_available": False,
            "transport_exposed_to_product": False,
            "physical_router_targeted": False,
            "production_allowed": False,
            "write_authorized": False,
            "acceptance": "FAIL",
        }
        rc = 17

    output.write_text(
        json.dumps(result, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    print(json.dumps(result, indent=2, sort_keys=True))
    return rc


if __name__ == "__main__":
    raise SystemExit(main())
