"""Transport-free execution contract for the Cisco C10 recovery plan.

This module freezes the recovery state-machine shape that a future authorized
NETCONF executor must obey. It does not import a NETCONF client, open sockets,
apply configuration, confirm a commit, or grant write authority.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass
import hashlib
import hmac
import json
from typing import Any

from .transaction_recovery import CiscoRecoveryPlan

_CANDIDATE_CAPABILITY = "urn:ietf:params:netconf:capability:candidate:1.0"
_CONFIRMED_COMMIT_PREFIX = "urn:ietf:params:netconf:capability:confirmed-commit:"
_EXPECTED_TIMEOUT_SECONDS = 600
_EXPECTED_PHASES = (
    "revalidate_exact_target_version_schema_pre_state_and_approval",
    "revalidate_repository_safe_prechange_snapshot",
    "lock_running_datastore",
    "lock_candidate_datastore",
    "apply_exact_approved_candidate",
    "issue_confirmed_commit_using_documented_default_timeout",
    "verify_management_path",
    "verify_connectivity_baseline",
    "verify_intended_state",
    "confirm_commit_permanently_only_if_all_verifications_pass",
    "otherwise_withhold_confirmation_and_allow_automatic_rollback",
    "verify_recovered_management_connectivity_and_prechange_state",
    "unlock_candidate_and_running_datastores",
)


class CiscoRecoveryExecutionContractError(ValueError):
    """Raised when a recovery plan cannot safely enter an executor boundary."""


def _canonical_sha256(value: object) -> str:
    raw = json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        default=str,
    ).encode("utf-8")
    return hashlib.sha256(raw).hexdigest()


@dataclass(frozen=True)
class CiscoRecoveryExecutionContract:
    target_id: str
    model: str
    iosxe_version: str
    recovery_plan_sha256: str
    approval_sha256: str
    c09_bundle_sha256: str
    backup_evidence_sha256: str
    confirmed_commit_capability: str
    confirmed_commit_timeout_seconds: int
    phase_order: tuple[str, ...]
    contract_sha256: str
    transport: str = "netconf"
    candidate_datastore_required: bool = True
    confirmation_requires_all_verifications: bool = True
    automatic_rollback_on_unconfirmed_change: bool = True
    executor_implementation_present: bool = False
    live_execution_observed: bool = False
    live_rollback_observed: bool = False
    restored_state_verified: bool = False
    c10_complete: bool = False
    production_writer_available: bool = False
    production_write_authorized: bool = False

    def as_dict(self) -> dict[str, Any]:
        payload = asdict(self)
        payload["phase_order"] = list(self.phase_order)
        payload["schema_version"] = "cisco-recovery-execution-contract/1"
        return payload


def validate_recovery_plan_for_executor(plan: CiscoRecoveryPlan) -> None:
    """Verify plan integrity and every fail-closed executor prerequisite."""

    payload = plan.as_dict()
    supplied = str(payload.pop("plan_sha256", "")).strip().lower()
    expected = _canonical_sha256(payload)
    if not hmac.compare_digest(supplied, expected):
        raise CiscoRecoveryExecutionContractError("recovery plan digest mismatch")

    if plan.transport != "netconf":
        raise CiscoRecoveryExecutionContractError("C10 executor contract requires NETCONF")
    if plan.candidate_capability != _CANDIDATE_CAPABILITY:
        raise CiscoRecoveryExecutionContractError("candidate capability binding mismatch")
    if not plan.confirmed_commit_capability.startswith(_CONFIRMED_COMMIT_PREFIX):
        raise CiscoRecoveryExecutionContractError("confirmed-commit capability binding mismatch")
    if plan.confirmed_commit_timeout_seconds != _EXPECTED_TIMEOUT_SECONDS:
        raise CiscoRecoveryExecutionContractError("confirmed-commit timeout differs from source-bound recovery plan")
    if tuple(plan.required_runtime_order) != _EXPECTED_PHASES:
        raise CiscoRecoveryExecutionContractError("recovery phase order mismatch")
    if plan.restconf_confirmed_commit_allowed:
        raise CiscoRecoveryExecutionContractError("RESTCONF confirmed commit must remain disabled")
    if not plan.automatic_rollback_required:
        raise CiscoRecoveryExecutionContractError("automatic rollback must remain mandatory")
    if not plan.final_confirmation_requires_all_verifications:
        raise CiscoRecoveryExecutionContractError("final confirmation must require all verifications")
    if plan.c10_complete or plan.apply_available:
        raise CiscoRecoveryExecutionContractError("pre-executor recovery plan cannot claim C10 completion or apply availability")
    if plan.production_writer_available or plan.production_write_authorized:
        raise CiscoRecoveryExecutionContractError("recovery plan cannot expose production write authority")


def build_recovery_execution_contract(plan: CiscoRecoveryPlan) -> CiscoRecoveryExecutionContract:
    """Bind a validated C10 plan into a transport-free future-executor contract."""

    validate_recovery_plan_for_executor(plan)
    unsigned = {
        "schema_version": "cisco-recovery-execution-contract/1",
        "target_id": plan.target_id,
        "model": plan.model,
        "iosxe_version": plan.iosxe_version,
        "recovery_plan_sha256": plan.plan_sha256,
        "approval_sha256": plan.approval_sha256,
        "c09_bundle_sha256": plan.c09_bundle_sha256,
        "backup_evidence_sha256": plan.backup_evidence_sha256,
        "confirmed_commit_capability": plan.confirmed_commit_capability,
        "confirmed_commit_timeout_seconds": plan.confirmed_commit_timeout_seconds,
        "phase_order": list(_EXPECTED_PHASES),
        "transport": "netconf",
        "candidate_datastore_required": True,
        "confirmation_requires_all_verifications": True,
        "automatic_rollback_on_unconfirmed_change": True,
        "executor_implementation_present": False,
        "live_execution_observed": False,
        "live_rollback_observed": False,
        "restored_state_verified": False,
        "c10_complete": False,
        "production_writer_available": False,
        "production_write_authorized": False,
    }
    return CiscoRecoveryExecutionContract(
        target_id=plan.target_id,
        model=plan.model,
        iosxe_version=plan.iosxe_version,
        recovery_plan_sha256=plan.plan_sha256,
        approval_sha256=plan.approval_sha256,
        c09_bundle_sha256=plan.c09_bundle_sha256,
        backup_evidence_sha256=plan.backup_evidence_sha256,
        confirmed_commit_capability=plan.confirmed_commit_capability,
        confirmed_commit_timeout_seconds=plan.confirmed_commit_timeout_seconds,
        phase_order=_EXPECTED_PHASES,
        contract_sha256=_canonical_sha256(unsigned),
    )


def contract_only_status() -> dict[str, Any]:
    payload = {
        "schema_version": "cisco-c10-executor-contract-status/1",
        "transport": "netconf",
        "phase_count": len(_EXPECTED_PHASES),
        "confirmed_commit_timeout_seconds": _EXPECTED_TIMEOUT_SECONDS,
        "executor_implementation_present": False,
        "synthetic_fixture_can_complete_c10": False,
        "live_execution_observed": False,
        "live_rollback_observed": False,
        "restored_state_verified": False,
        "c10_complete": False,
        "production_writer_available": False,
        "production_write_authorized": False,
    }
    payload["status_sha256"] = _canonical_sha256(payload)
    return payload
