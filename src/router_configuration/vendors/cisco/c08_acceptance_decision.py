"""Repository acceptance decision for reviewed Cisco C08 human approval evidence.

Acceptance records that the exact immutable approval fingerprint and detached
human approval evidence were accepted. It deliberately does not turn approval
into apply/write authorization; execution remains a separate later gate.
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


class CiscoC08AcceptanceDecisionError(ValueError):
    pass


def _canonical_sha256(value: object) -> str:
    return hashlib.sha256(
        json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
    ).hexdigest()


def _sha(value: object, label: str) -> str:
    text = str(value or "").strip().lower()
    if not _SHA256_RE.fullmatch(text):
        raise CiscoC08AcceptanceDecisionError(f"{label} must be lowercase SHA-256")
    return text


def bind_c08_repository_decision(
    review_candidate: Mapping[str, Any],
    *,
    decision_id: str,
    authority_ref: str,
    authority_attestation_sha256: str,
    decision: str,
) -> dict[str, Any]:
    if review_candidate.get("schema_version") != "cisco-c08-human-approval-review-candidate/1":
        raise CiscoC08AcceptanceDecisionError("unexpected C08 review candidate schema")

    supplied = _sha(review_candidate.get("review_candidate_sha256"), "review_candidate_sha256")
    unsigned = dict(review_candidate)
    unsigned.pop("review_candidate_sha256", None)
    if not hmac.compare_digest(supplied, _canonical_sha256(unsigned)):
        raise CiscoC08AcceptanceDecisionError("C08 review candidate digest mismatch")

    if review_candidate.get("eligible_for_repository_acceptance") is not True:
        raise CiscoC08AcceptanceDecisionError("C08 review candidate is not eligible for repository acceptance")
    for field in ("human_approved", "approval_bound", "c08_complete", "apply_authorized", "write_authorized", "production_write_authorized"):
        if review_candidate.get(field) is not False:
            raise CiscoC08AcceptanceDecisionError(f"C08 review candidate crossed acceptance boundary: {field}")

    did = str(decision_id).strip()
    authority = str(authority_ref).strip()
    if not _REF_RE.fullmatch(did) or not _REF_RE.fullmatch(authority):
        raise CiscoC08AcceptanceDecisionError("invalid C08 decision identity")
    normalized_decision = str(decision).strip().lower()
    if normalized_decision not in _DECISIONS:
        raise CiscoC08AcceptanceDecisionError("unsupported C08 decision")
    attestation = _sha(authority_attestation_sha256, "authority_attestation_sha256")

    accepted = normalized_decision == "accept"
    result = {
        "schema_version": "cisco-c08-repository-acceptance-decision/1",
        "decision_id": did,
        "authority_ref": authority,
        "authority_attestation_sha256": attestation,
        "decision": normalized_decision,
        "review_candidate_sha256": supplied,
        "approval_sha256": _sha(review_candidate.get("approval_sha256"), "approval_sha256"),
        "pre_state_sha256": _sha(review_candidate.get("pre_state_sha256"), "pre_state_sha256"),
        "change_id": str(review_candidate.get("change_id", "")),
        "target_id": str(review_candidate.get("target_id", "")),
        "human_approved": accepted,
        "approval_bound": accepted,
        "c08_complete": accepted,
        "apply_authorized": False,
        "write_authorized": False,
        "production_write_authorized": False,
    }
    result["decision_record_sha256"] = _canonical_sha256(result)
    return result
