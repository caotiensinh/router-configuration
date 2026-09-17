"""Final repository decision binding for reviewed Cisco C06 switch-state evidence.

The function consumes the immutable C06 review candidate and records an explicit
accept/reject decision. Acceptance completes only the repository C06 evidence
gate; it does not claim physical-device verification or production authority.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import re
from typing import Any, Mapping

_SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
_REF_RE = re.compile(r"^[A-Za-z0-9_.:@/-]{1,128}$")
_DECISIONS = frozenset({"accept", "reject"})


class CiscoC06AcceptanceDecisionError(ValueError):
    pass


def _canonical_sha256(value: object) -> str:
    return hashlib.sha256(
        json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
    ).hexdigest()


def _sha(value: object, label: str) -> str:
    text = str(value or "").strip().lower()
    if not _SHA256_RE.fullmatch(text):
        raise CiscoC06AcceptanceDecisionError(f"{label} must be lowercase SHA-256")
    return text


def bind_c06_repository_decision(
    review_candidate: Mapping[str, Any],
    *,
    decision_id: str,
    authority_ref: str,
    authority_attestation_sha256: str,
    decision: str,
) -> dict[str, Any]:
    if review_candidate.get("schema_version") != "cisco-c06-acceptance-review-candidate/1":
        raise CiscoC06AcceptanceDecisionError("unexpected C06 review candidate schema")

    supplied = _sha(review_candidate.get("review_candidate_sha256"), "review_candidate_sha256")
    unsigned = dict(review_candidate)
    unsigned.pop("review_candidate_sha256", None)
    if not hmac.compare_digest(supplied, _canonical_sha256(unsigned)):
        raise CiscoC06AcceptanceDecisionError("C06 review candidate digest mismatch")

    if review_candidate.get("eligible_for_repository_acceptance") is not True:
        raise CiscoC06AcceptanceDecisionError("C06 review candidate is not eligible for repository acceptance")
    for field in (
        "repository_live_evidence_accepted",
        "c06_complete",
        "physical_device_verified",
        "production_write_authorized",
    ):
        if review_candidate.get(field) is not False:
            raise CiscoC06AcceptanceDecisionError(f"C06 review candidate crossed acceptance boundary: {field}")

    did = str(decision_id).strip()
    authority = str(authority_ref).strip()
    if not _REF_RE.fullmatch(did) or not _REF_RE.fullmatch(authority):
        raise CiscoC06AcceptanceDecisionError("invalid C06 decision identity")
    normalized_decision = str(decision).strip().lower()
    if normalized_decision not in _DECISIONS:
        raise CiscoC06AcceptanceDecisionError("unsupported C06 decision")
    attestation = _sha(authority_attestation_sha256, "authority_attestation_sha256")

    accepted = normalized_decision == "accept"
    result = {
        "schema_version": "cisco-c06-repository-acceptance-decision/1",
        "decision_id": did,
        "authority_ref": authority,
        "authority_attestation_sha256": attestation,
        "decision": normalized_decision,
        "review_candidate_sha256": supplied,
        "ingest_record_sha256": _sha(review_candidate.get("ingest_record_sha256"), "ingest_record_sha256"),
        "state_digest_sha256": _sha(review_candidate.get("state_digest_sha256"), "state_digest_sha256"),
        "target_id": str(review_candidate.get("target_id", "")),
        "model": str(review_candidate.get("model", "")),
        "iosxe_version": str(review_candidate.get("iosxe_version", "")),
        "repository_live_evidence_accepted": accepted,
        "c06_complete": accepted,
        "physical_device_verified": False,
        "production_write_authorized": False,
    }
    result["decision_record_sha256"] = _canonical_sha256(result)
    return result
