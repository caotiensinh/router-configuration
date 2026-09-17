"""Repository-review candidate boundary for observed Cisco C10 recovery runs.

The module verifies the observation digest and recovery outcome before binding a
detached reviewer attestation. It never promotes the observation into accepted
C10 evidence or production write authority.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import re
from typing import Any

from .recovery_observation import CiscoRecoveryObservation

_SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
_REF_RE = re.compile(r"^[A-Za-z0-9_.:@/-]{1,128}$")


class CiscoC10RecoveryReviewError(ValueError):
    """Raised when a C10 recovery review candidate fails closed."""


def _canonical_sha256(value: object) -> str:
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")).hexdigest()


def _sha(value: object, label: str) -> str:
    text = str(value or "").strip().lower()
    if not _SHA256_RE.fullmatch(text):
        raise CiscoC10RecoveryReviewError(f"{label} must be lowercase SHA-256")
    return text


def build_c10_recovery_review_candidate(
    observation: CiscoRecoveryObservation,
    *,
    review_id: str,
    reviewer_ref: str,
    reviewer_attestation_sha256: str,
) -> dict[str, Any]:
    payload = observation.as_dict()
    supplied = _sha(payload.pop("observation_sha256", ""), "observation_sha256")
    if not hmac.compare_digest(supplied, _canonical_sha256(payload)):
        raise CiscoC10RecoveryReviewError("C10 recovery observation digest mismatch")

    if not observation.candidate_claims_live_execution:
        raise CiscoC10RecoveryReviewError("C10 candidate lacks live execution evidence")
    if observation.outcome == "automatic_rollback":
        if not observation.candidate_claims_live_rollback or not observation.candidate_claims_restored_state_verified:
            raise CiscoC10RecoveryReviewError("rollback review requires observed rollback and restored state")
    elif observation.outcome == "confirmed":
        if observation.candidate_claims_live_rollback:
            raise CiscoC10RecoveryReviewError("confirmed observation cannot also claim rollback")
    else:
        raise CiscoC10RecoveryReviewError("unsupported C10 recovery outcome")

    if observation.repository_live_evidence_accepted or observation.c10_complete or observation.physical_device_verified:
        raise CiscoC10RecoveryReviewError("C10 observation crossed repository acceptance boundary")
    if observation.production_writer_available or observation.production_write_authorized:
        raise CiscoC10RecoveryReviewError("C10 observation cannot carry production write authority")

    rid = str(review_id).strip()
    reviewer = str(reviewer_ref).strip()
    if not _REF_RE.fullmatch(rid) or not _REF_RE.fullmatch(reviewer):
        raise CiscoC10RecoveryReviewError("invalid C10 review identity")
    attestation = _sha(reviewer_attestation_sha256, "reviewer_attestation_sha256")

    result = {
        "schema_version": "cisco-c10-recovery-review-candidate/1",
        "review_id": rid,
        "reviewer_ref": reviewer,
        "reviewer_attestation_sha256": attestation,
        "target_id": observation.target_id,
        "model": observation.model,
        "iosxe_version": observation.iosxe_version,
        "observation_sha256": supplied,
        "recovery_plan_sha256": observation.recovery_plan_sha256,
        "execution_contract_sha256": observation.execution_contract_sha256,
        "outcome": observation.outcome,
        "eligible_for_repository_acceptance": True,
        "repository_live_evidence_accepted": False,
        "c10_complete": False,
        "physical_device_verified": False,
        "production_writer_available": False,
        "production_write_authorized": False,
    }
    result["review_candidate_sha256"] = _canonical_sha256(result)
    return result
