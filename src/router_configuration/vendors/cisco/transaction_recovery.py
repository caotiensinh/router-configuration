"""Cisco IOS XE transaction backup and confirmed-commit recovery contract.

This module plans a future authorized lab/production transaction. It deliberately
contains no NETCONF transport, credentials, device endpoint, or write method.
Cisco IOS XE recovery is source-bound to candidate datastore plus confirmed
commit semantics; an executor is a later boundary.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass
import hashlib
import hmac
import json
import re
from typing import Any, Iterable, Mapping

from .validation_approval import CiscoApprovalBinding

_CANDIDATE_CAPABILITY = "urn:ietf:params:netconf:capability:candidate:1.0"
_CONFIRMED_COMMIT_PREFIX = "urn:ietf:params:netconf:capability:confirmed-commit:"
_DEFAULT_CONFIRMED_COMMIT_TIMEOUT_SECONDS = 600
_SHA256 = re.compile(r"^[0-9a-f]{64}$")
_OPAQUE_ID = re.compile(r"^[A-Za-z0-9_.:/-]{1,160}$")
_FORBIDDEN_REFERENCE_MARKERS = (
    "http://",
    "https://",
    "password",
    "passwd",
    "token",
    "secret",
    "private_key",
)


class CiscoTransactionRecoveryError(ValueError):
    """Raised when a C10 transaction/recovery binding fails closed."""


def _canonical_sha256(value: object) -> str:
    raw = json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        default=str,
    ).encode("utf-8")
    return hashlib.sha256(raw).hexdigest()


def _digest(value: object, label: str) -> str:
    text = str(value or "").strip().lower()
    if not _SHA256.fullmatch(text):
        raise CiscoTransactionRecoveryError(f"{label} must be a lowercase SHA-256 digest")
    return text


def _opaque(value: object, label: str) -> str:
    text = str(value or "").strip()
    lowered = text.lower()
    if not _OPAQUE_ID.fullmatch(text) or any(marker in lowered for marker in _FORBIDDEN_REFERENCE_MARKERS):
        raise CiscoTransactionRecoveryError(f"{label} must be an opaque non-secret reference")
    return text


@dataclass(frozen=True)
class CiscoBackupEvidence:
    target_id: str
    model: str
    iosxe_version: str
    pre_state_sha256: str
    snapshot_ref: str
    snapshot_sha256: str
    evidence_sha256: str
    readable: bool = True
    repository_safe: bool = True
    secret_values_present: bool = False
    binary_payload_present: bool = False
    production_writer_available: bool = False
    production_write_authorized: bool = False

    def as_dict(self) -> dict[str, Any]:
        payload = asdict(self)
        payload["schema_version"] = "cisco-transaction-backup-evidence/1"
        return payload


@dataclass(frozen=True)
class CiscoRecoveryPlan:
    target_id: str
    model: str
    iosxe_version: str
    pre_state_sha256: str
    payload_digest_sha256: str
    approval_sha256: str
    c09_bundle_sha256: str
    backup_evidence_sha256: str
    management_baseline_sha256: str
    connectivity_baseline_sha256: str
    candidate_capability: str
    confirmed_commit_capability: str
    confirmed_commit_timeout_seconds: int
    required_runtime_order: tuple[str, ...]
    plan_sha256: str
    transport: str = "netconf"
    restconf_confirmed_commit_allowed: bool = False
    automatic_rollback_required: bool = True
    final_confirmation_requires_all_verifications: bool = True
    c10_complete: bool = False
    apply_available: bool = False
    production_writer_available: bool = False
    production_write_authorized: bool = False

    def as_dict(self) -> dict[str, Any]:
        payload = asdict(self)
        payload["required_runtime_order"] = list(self.required_runtime_order)
        payload["schema_version"] = "cisco-transaction-recovery-plan/1"
        return payload


def build_cisco_backup_evidence(
    *,
    target_id: str,
    model: str,
    iosxe_version: str,
    pre_state_sha256: str,
    snapshot_ref: str,
    snapshot_sha256: str,
) -> CiscoBackupEvidence:
    """Create repository-safe evidence for a sanitized pre-change snapshot."""

    target = _opaque(target_id, "target_id")
    model_text = str(model or "").strip()
    version_text = str(iosxe_version or "").strip()
    if not model_text or not version_text:
        raise CiscoTransactionRecoveryError("model and iosxe_version are required")
    state_sha = _digest(pre_state_sha256, "pre_state_sha256")
    ref = _opaque(snapshot_ref, "snapshot_ref")
    if not ref.startswith("artifact:"):
        raise CiscoTransactionRecoveryError("snapshot_ref must use an opaque artifact: reference")
    snapshot_sha = _digest(snapshot_sha256, "snapshot_sha256")
    unsigned = {
        "schema_version": "cisco-transaction-backup-evidence/1",
        "target_id": target,
        "model": model_text,
        "iosxe_version": version_text,
        "pre_state_sha256": state_sha,
        "snapshot_ref": ref,
        "snapshot_sha256": snapshot_sha,
        "readable": True,
        "repository_safe": True,
        "secret_values_present": False,
        "binary_payload_present": False,
        "production_writer_available": False,
        "production_write_authorized": False,
    }
    return CiscoBackupEvidence(
        target_id=target,
        model=model_text,
        iosxe_version=version_text,
        pre_state_sha256=state_sha,
        snapshot_ref=ref,
        snapshot_sha256=snapshot_sha,
        evidence_sha256=_canonical_sha256(unsigned),
    )


def validate_cisco_backup_evidence(evidence: CiscoBackupEvidence) -> None:
    """Verify the backup object is intact and does not carry write/secrets claims."""

    if not evidence.readable or not evidence.repository_safe:
        raise CiscoTransactionRecoveryError("backup evidence must be readable and repository safe")
    if evidence.secret_values_present or evidence.binary_payload_present:
        raise CiscoTransactionRecoveryError("backup evidence must not embed secrets or binary payloads")
    if evidence.production_writer_available or evidence.production_write_authorized:
        raise CiscoTransactionRecoveryError("backup evidence must not expose production write authority")
    _opaque(evidence.target_id, "backup.target_id")
    _opaque(evidence.snapshot_ref, "backup.snapshot_ref")
    if not evidence.snapshot_ref.startswith("artifact:"):
        raise CiscoTransactionRecoveryError("backup snapshot reference must use artifact:")
    _digest(evidence.pre_state_sha256, "backup.pre_state_sha256")
    _digest(evidence.snapshot_sha256, "backup.snapshot_sha256")
    supplied = _digest(evidence.evidence_sha256, "backup.evidence_sha256")
    unsigned = evidence.as_dict()
    unsigned.pop("evidence_sha256", None)
    if not hmac.compare_digest(supplied, _canonical_sha256(unsigned)):
        raise CiscoTransactionRecoveryError("backup evidence digest mismatch")


def _confirmed_commit_capability(capabilities: Iterable[str]) -> str:
    values = {str(item).strip() for item in capabilities if str(item).strip()}
    if _CANDIDATE_CAPABILITY not in values:
        raise CiscoTransactionRecoveryError("NETCONF candidate capability was not observed")
    confirmed = sorted(item for item in values if item.startswith(_CONFIRMED_COMMIT_PREFIX))
    if not confirmed:
        raise CiscoTransactionRecoveryError("NETCONF confirmed-commit capability was not observed")
    if len(confirmed) != 1:
        raise CiscoTransactionRecoveryError("ambiguous confirmed-commit capability set")
    return confirmed[0]


def build_cisco_recovery_plan(
    *,
    approval: CiscoApprovalBinding,
    backup: CiscoBackupEvidence,
    c09_bundle_sha256: str,
    management_baseline_sha256: str,
    connectivity_baseline_sha256: str,
    observed_netconf_capabilities: Iterable[str],
) -> CiscoRecoveryPlan:
    """Build the deterministic C10 recovery plan without exposing an executor."""

    if (
        approval.apply_authorized
        or approval.write_authorized
        or approval.production_write_authorized
        or approval.human_approved
    ):
        raise CiscoTransactionRecoveryError("C08 approval binding must remain a pre-write fingerprint")
    if approval.target_datastore != "candidate":
        raise CiscoTransactionRecoveryError("C10 confirmed-commit recovery requires candidate datastore")

    validate_cisco_backup_evidence(backup)
    if backup.target_id != approval.target_id:
        raise CiscoTransactionRecoveryError("backup target differs from C08 approval target")
    if backup.model != approval.model or backup.iosxe_version != approval.iosxe_version:
        raise CiscoTransactionRecoveryError("backup platform/version differs from C08 approval")
    if backup.pre_state_sha256 != approval.pre_state_sha256:
        raise CiscoTransactionRecoveryError("backup pre-state differs from C08 approval")

    c09_sha = _digest(c09_bundle_sha256, "c09_bundle_sha256")
    management_sha = _digest(management_baseline_sha256, "management_baseline_sha256")
    connectivity_sha = _digest(connectivity_baseline_sha256, "connectivity_baseline_sha256")
    confirmed = _confirmed_commit_capability(observed_netconf_capabilities)

    runtime_order = (
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
    unsigned = {
        "schema_version": "cisco-transaction-recovery-plan/1",
        "target_id": approval.target_id,
        "model": approval.model,
        "iosxe_version": approval.iosxe_version,
        "pre_state_sha256": approval.pre_state_sha256,
        "payload_digest_sha256": approval.payload_digest_sha256,
        "approval_sha256": approval.approval_sha256,
        "c09_bundle_sha256": c09_sha,
        "backup_evidence_sha256": backup.evidence_sha256,
        "management_baseline_sha256": management_sha,
        "connectivity_baseline_sha256": connectivity_sha,
        "candidate_capability": _CANDIDATE_CAPABILITY,
        "confirmed_commit_capability": confirmed,
        "confirmed_commit_timeout_seconds": _DEFAULT_CONFIRMED_COMMIT_TIMEOUT_SECONDS,
        "required_runtime_order": list(runtime_order),
        "transport": "netconf",
        "restconf_confirmed_commit_allowed": False,
        "automatic_rollback_required": True,
        "final_confirmation_requires_all_verifications": True,
        "c10_complete": False,
        "apply_available": False,
        "production_writer_available": False,
        "production_write_authorized": False,
    }
    return CiscoRecoveryPlan(
        target_id=approval.target_id,
        model=approval.model,
        iosxe_version=approval.iosxe_version,
        pre_state_sha256=approval.pre_state_sha256,
        payload_digest_sha256=approval.payload_digest_sha256,
        approval_sha256=approval.approval_sha256,
        c09_bundle_sha256=c09_sha,
        backup_evidence_sha256=backup.evidence_sha256,
        management_baseline_sha256=management_sha,
        connectivity_baseline_sha256=connectivity_sha,
        candidate_capability=_CANDIDATE_CAPABILITY,
        confirmed_commit_capability=confirmed,
        confirmed_commit_timeout_seconds=_DEFAULT_CONFIRMED_COMMIT_TIMEOUT_SECONDS,
        required_runtime_order=runtime_order,
        plan_sha256=_canonical_sha256(unsigned),
    )


def contract_only_status() -> dict[str, Any]:
    payload = {
        "schema_version": "cisco-c10-contract-status/1",
        "recovery_primitive": "netconf_candidate_confirmed_commit",
        "documented_default_confirm_timeout_seconds": _DEFAULT_CONFIRMED_COMMIT_TIMEOUT_SECONDS,
        "restconf_confirmed_commit_allowed": False,
        "synthetic_fixture_can_complete_c10": False,
        "live_rollback_observed": False,
        "restored_state_verified": False,
        "c10_complete": False,
        "apply_available": False,
        "production_writer_available": False,
        "production_write_authorized": False,
    }
    payload["status_sha256"] = _canonical_sha256(payload)
    return payload
