"""Detached human-approval review boundary for Cisco C08 fingerprints.

The module binds an external approval attestation to the immutable C08 approval
fingerprint. It does not mutate the binding and cannot itself authorize writes.
"""

from __future__ import annotations

import hashlib
import json
import re
from typing import Any, Mapping

from .validation_approval import CiscoApprovalBinding, validate_approval_fingerprint

_SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
_REF_RE = re.compile(r"^[A-Za-z0-9_.:@/-]{1,128}$")


class CiscoC08HumanApprovalReviewError(ValueError):
    """Raised when detached approval evidence fails closed."""


def _canonical_sha256(value: object) -> str:
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")).hexdigest()


def _sha(value: object, label: str) -> str:
    text = str(value or "").strip().lower()
    if not _SHA256_RE.fullmatch(text):
        raise CiscoC08HumanApprovalReviewError(f"{label} must be lowercase SHA-256")
    return text


def build_c08_human_approval_review_candidate(
    evidence: Mapping[str, Any],
    *,
    binding: CiscoApprovalBinding,
) -> dict[str, Any]:
    if evidence.get("schema_version") != "cisco-c08-human-approval-evidence/1":
        raise CiscoC08HumanApprovalReviewError("unexpected C08 human approval schema")
    if binding.human_approved or binding.approval_bound or binding.c08_complete:
        raise CiscoC08HumanApprovalReviewError("C08 binding must remain pre-acceptance")
    if binding.apply_authorized or binding.write_authorized or binding.production_write_authorized:
        raise CiscoC08HumanApprovalReviewError("C08 binding cannot carry write authority")

    if evidence.get("decision") != "approved":
        raise CiscoC08HumanApprovalReviewError("human approval decision must be approved")
    if evidence.get("change_id") != binding.change_id or evidence.get("target_id") != binding.target_id:
        raise CiscoC08HumanApprovalReviewError("approval evidence target/change binding mismatch")
    if evidence.get("pre_state_sha256") != binding.pre_state_sha256:
        raise CiscoC08HumanApprovalReviewError("approval evidence pre-state mismatch")

    approved = _sha(evidence.get("approval_sha256"), "approval_sha256")
    validate_approval_fingerprint(binding, approved)
    approver = str(evidence.get("approver_ref", "")).strip()
    approval_record = str(evidence.get("approval_record_id", "")).strip()
    if not _REF_RE.fullmatch(approver) or not _REF_RE.fullmatch(approval_record):
        raise CiscoC08HumanApprovalReviewError("invalid approval evidence identity")
    attestation = _sha(evidence.get("approver_attestation_sha256"), "approver_attestation_sha256")
    if evidence.get("production_write_authorized") is not False:
        raise CiscoC08HumanApprovalReviewError("human approval evidence cannot authorize production write")

    result = {
        "schema_version": "cisco-c08-human-approval-review-candidate/1",
        "approval_record_id": approval_record,
        "approver_ref": approver,
        "approver_attestation_sha256": attestation,
        "change_id": binding.change_id,
        "target_id": binding.target_id,
        "pre_state_sha256": binding.pre_state_sha256,
        "approval_sha256": binding.approval_sha256,
        "eligible_for_repository_acceptance": True,
        "human_approved": False,
        "approval_bound": False,
        "c08_complete": False,
        "apply_authorized": False,
        "write_authorized": False,
        "production_write_authorized": False,
    }
    result["review_candidate_sha256"] = _canonical_sha256(result)
    return result
