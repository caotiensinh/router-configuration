from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any

import verify_mutation_rollback as runtime_rollback
import verify_render_dry_run as base
import verify_render_dry_run_chunked as chunked
import verify_transaction_runtime_admission as admission

from router_configuration.transaction_lifecycle import (
    TransactionLifecycleError,
    transition_transaction_lifecycle,
)


class CHRTransactionRecoveryVerificationError(RuntimeError):
    pass


def verify_transaction_recovery(
    *,
    admin_url: str,
    workflow_sha: str,
) -> dict[str, Any]:
    """Independently verify recovery after the admitted disposable-CHR runtime.

    The existing transaction admission verifier owns the mutation/failure/rollback
    lab. This wrapper deliberately waits for that runtime to return, then creates
    a fresh read-only REST helper and independently re-reads RouterOS state before
    allowing the audit lifecycle to transition from ``rollback_observed`` to
    ``rolled_back``.

    This gate proves recovery of the exact disposable-CHR fixture baseline only.
    It does not claim post-apply verification, WAN/DNS/VPN data-plane recovery,
    production management reachability, physical-router behavior or production
    write authorization.
    """

    result = admission.verify_transaction_runtime_admission(
        admin_url=admin_url,
        workflow_sha=workflow_sha,
    )
    if result.get("acceptance") != "PASS" or result.get("ok") is not True:
        raise CHRTransactionRecoveryVerificationError(
            "transaction runtime admission did not pass before recovery verification"
        )

    lifecycle = result.get("lifecycle")
    if not isinstance(lifecycle, dict) or lifecycle.get("phase") != "rollback_observed":
        raise CHRTransactionRecoveryVerificationError(
            "recovery verification requires rollback_observed lifecycle phase"
        )

    transaction = result.get("transaction")
    if not isinstance(transaction, dict):
        raise CHRTransactionRecoveryVerificationError(
            "transaction binding is missing from runtime evidence"
        )
    baseline_sha256 = str(transaction.get("pre_state_sha256") or "")
    if len(baseline_sha256) != 64:
        raise CHRTransactionRecoveryVerificationError(
            "runtime evidence does not contain the bound pre-state digest"
        )

    # Independent recovery verification begins only after the admitted runtime
    # has returned. Use a fresh helper so no runtime-local observation is trusted.
    recovery_admin = base.LoopbackCHRAdmin(admin_url)
    platform = recovery_admin.assert_disposable_chr()
    interface_names = admission._required_interfaces(recovery_admin)
    runtime_rollback._assert_managed_state_absent(recovery_admin)

    recovered_state = chunked._configuration_snapshot_with_pcc(recovery_admin)
    recovered_sha256 = base._canonical_digest(recovered_state)
    if recovered_sha256 != baseline_sha256:
        raise CHRTransactionRecoveryVerificationError(
            "independent recovery digest does not match the transaction pre-state"
        )

    recovery = {
        "schema_version": "routeros-transaction-recovery-verification/1",
        "workflow_sha": str(result.get("workflow_sha") or ""),
        "fresh_rest_session": True,
        "runtime_result_reused_for_recovery_state": False,
        "management_rest_recovered": True,
        "fixture_connectivity_baseline_recovered": True,
        "managed_objects_reconciled": True,
        "required_interfaces": interface_names,
        "rollback_state_sha256": recovered_sha256,
        "pre_state_sha256": baseline_sha256,
        "rollback_digest_matches_pre_state": recovered_sha256 == baseline_sha256,
        "platform": {
            "version": str(platform.get("version") or ""),
            "architecture": str(platform.get("architecture-name") or ""),
            "board_name": str(platform.get("board-name") or ""),
        },
        "raw_configuration_recorded": False,
        "secret_values_present": False,
        "post_apply_verification_claimed": False,
        "wan_dns_vpn_recovery_claimed": False,
        "production_management_reachability_claimed": False,
    }

    lifecycle = transition_transaction_lifecycle(
        lifecycle=lifecycle,
        to_phase="rolled_back",
        evidence={
            "evidence_ref": "runtime-evidence/disposable-chr/independent-recovery-verification",
            "management_recovered": True,
            "connectivity_recovered": True,
            "managed_objects_reconciled": True,
            "rollback_state_sha256": recovered_sha256,
        },
    ).as_dict()

    result = dict(result)
    result["scope"] = "disposable_chr_transaction_independent_recovery_verification"
    result["lifecycle"] = lifecycle
    result["recovery_verification"] = recovery
    result["recovery_verification_claimed"] = True
    result["post_apply_verification_claimed"] = False
    result["management_survival_during_apply_claimed"] = False
    result["wan_dns_vpn_recovery_claimed"] = False
    result["production_management_reachability_claimed"] = False
    result["production_writer_available"] = False
    result["transport_exposed_to_product"] = False
    result["physical_router_targeted"] = False
    result["production_allowed"] = False
    result["write_authorized"] = False
    result["acceptance"] = "PASS"
    result["ok"] = True
    return result


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
        CHRTransactionRecoveryVerificationError,
        TransactionLifecycleError,
        base.CHRRenderDryRunError,
        runtime_rollback.CHRMutationRollbackError,
        admission.CHRTransactionRuntimeAdmissionError,
    ) as exc:
        result = {
            "ok": False,
            "error": str(exc),
            "recovery_verification_claimed": False,
            "post_apply_verification_claimed": False,
            "management_survival_during_apply_claimed": False,
            "wan_dns_vpn_recovery_claimed": False,
            "production_management_reachability_claimed": False,
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
