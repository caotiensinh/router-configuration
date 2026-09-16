"""Repository acceptance decision binding for reviewed Cisco C04 evidence.

The input must be the immutable review record produced by
``verify_c04_live_evidence``. The decision can accept or reject that exact record
without granting physical-device or production-write authority.
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


class CiscoC04AcceptanceDecisionError(ValueError):
    pass


def _canonical_sha256(value: object) -> str:
    return hashlib.sha256(
        json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
    ).hexdigest()


def _sha(value: object, label: str) -> str:
    text = str(value or "").strip().lower()
    if not _SHA256_RE.fullmatch(text):
        raise CiscoC04AcceptanceDecisionError(f"{label} must be lowercase SHA-256")
    return text


def bind_c04_repository_decision(
    review_record: Mapping[str, Any],
    *,
    decision_id: str,
    authority_ref: str,
    authority_attestation_sha256: str,
    decision: str,
) -> dict[str, Any]:
    if review_record.get("schema_version") != "cisco-c04-repository-review/1":
        raise CiscoC04AcceptanceDecisionError("unexpected C04 review schema")

    supplied = _sha(review_record.get("review_record_sha256"), "review_record_sha256")
    unsigned = dict(review_record)
    unsigned.pop("review_record_sha256", None)
    if not hmac.compare_digest(supplied, _canonical_sha256(unsigned)):
        raise CiscoC04AcceptanceDecisionError("C04 review record digest mismatch")

    for field in (
        "candidate_live_claim_valid",
        "get_only_verified",
        "tls_verified",
        "redirects_disabled",
        "platform_binding_verified",
    ):
        if review_record.get(field) is not True:
            raise CiscoC04AcceptanceDecisionError(f"C04 review invariant missing: {field}")
    for field in (
        "repository_evidence_accepted",
        "repository_c04_complete",
        "production_write_authorized",
        "physical_device_verified",
    ):
        if review_record.get(field) is not False:
            raise CiscoC04AcceptanceDecisionError(f"C04 review crossed acceptance boundary: {field}")

    did = str(decision_id).strip()
    authority = str(authority_ref).strip()
    if not _REF_RE.fullmatch(did) or not _REF_RE.fullmatch(authority):
        raise CiscoC04AcceptanceDecisionError("invalid C04 decision identity")
    normalized_decision = str(decision).strip().lower()
    if normalized_decision not in _DECISIONS:
        raise CiscoC04AcceptanceDecisionError("unsupported C04 decision")
    attestation = _sha(authority_attestation_sha256, "authority_attestation_sha256")

    accepted = normalized_decision == "accept"
    result = {
        "schema_version": "cisco-c04-repository-acceptance-decision/1",
        "review_record_sha256": supplied,
        "source_evidence_digest_sha256": _sha(
            review_record.get("source_evidence_digest_sha256"), "source_evidence_digest_sha256"
        ),
        "decision_id": did,
        "authority_ref": authority,
        "authority_attestation_sha256": attestation,
        "decision": normalized_decision,
        "repository_evidence_accepted": accepted,
        "repository_c04_complete": accepted,
        "physical_device_verified": False,
        "production_write_authorized": False,
    }
    result["decision_record_sha256"] = _canonical_sha256(result)
    return result
