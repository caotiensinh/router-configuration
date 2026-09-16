"""Detached decision binding for Cisco C11 physical evidence review.

This module binds a reviewer decision to the exact existing human-review
candidate. It records approve/reject intent but deliberately cannot mark physical
evidence accepted, complete C11, or grant production authority.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import re
from typing import Any, Mapping

_SHA256 = re.compile(r"^[0-9a-f]{64}$")
_REF = re.compile(r"^[A-Za-z0-9_.:@/-]{1,128}$")
_DECISIONS = frozenset({"approve", "reject"})


class CiscoC11ReviewDecisionError(ValueError):
    pass


def _canonical_sha256(value: object) -> str:
    return hashlib.sha256(
        json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
    ).hexdigest()


def _sha(value: object, label: str) -> str:
    text = str(value or "").strip().lower()
    if not _SHA256.fullmatch(text):
        raise CiscoC11ReviewDecisionError(f"{label} must be lowercase SHA-256")
    return text


def bind_c11_review_decision(
    review_candidate: Mapping[str, Any],
    *,
    decision_id: str,
    decision: str,
    decision_attestation_sha256: str,
) -> dict[str, Any]:
    if review_candidate.get("schema_version") != "cisco-c11-human-review-candidate/1":
        raise CiscoC11ReviewDecisionError("unexpected C11 human-review schema")

    supplied = _sha(review_candidate.get("review_candidate_sha256"), "review_candidate_sha256")
    unsigned = dict(review_candidate)
    unsigned.pop("review_candidate_sha256", None)
    if not hmac.compare_digest(supplied, _canonical_sha256(unsigned)):
        raise CiscoC11ReviewDecisionError("C11 human-review candidate digest mismatch")

    if review_candidate.get("eligible_for_repository_acceptance") is not True:
        raise CiscoC11ReviewDecisionError("human-review candidate is not eligible for repository review")
    for field in (
        "repository_physical_evidence_accepted",
        "c11_complete",
        "physical_device_verified",
        "production_write_authorized",
    ):
        if review_candidate.get(field) is not False:
            raise CiscoC11ReviewDecisionError(f"human-review candidate crossed acceptance boundary: {field}")

    did = str(decision_id).strip()
    if not _REF.fullmatch(did):
        raise CiscoC11ReviewDecisionError("invalid decision_id")
    normalized_decision = str(decision).strip().lower()
    if normalized_decision not in _DECISIONS:
        raise CiscoC11ReviewDecisionError("unsupported C11 review decision")
    attestation = _sha(decision_attestation_sha256, "decision_attestation_sha256")

    result = {
        "schema_version": "cisco-c11-review-decision-candidate/1",
        "decision_id": did,
        "decision": normalized_decision,
        "decision_attestation_sha256": attestation,
        "review_candidate_sha256": supplied,
        "ingest_record_sha256": _sha(review_candidate.get("ingest_record_sha256"), "ingest_record_sha256"),
        "claim_contract_digest_sha256": _sha(
            review_candidate.get("claim_contract_digest_sha256"), "claim_contract_digest_sha256"
        ),
        "target_kind": str(review_candidate.get("target_kind", "")),
        "model": str(review_candidate.get("model", "")),
        "iosxe_version": str(review_candidate.get("iosxe_version", "")),
        "platform_family": str(review_candidate.get("platform_family", "")),
        "candidate_human_decision_recorded": True,
        "repository_physical_evidence_accepted": False,
        "c11_complete": False,
        "physical_device_verified": False,
        "production_write_authorized": False,
    }
    result["decision_record_sha256"] = _canonical_sha256(result)
    return result
