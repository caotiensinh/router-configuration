"""Human-review candidate boundary for C06 live switch-state evidence.

This module validates an already-ingested C06 live evidence record and binds it
to a detached reviewer attestation. It never promotes evidence to repository
acceptance and never grants write authority.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import re
from typing import Any, Mapping

_SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
_REF_RE = re.compile(r"^[A-Za-z0-9_.:@/-]{1,128}$")


class CiscoC06AcceptanceReviewError(ValueError):
    """Raised when a C06 review candidate fails closed."""


def _canonical_sha256(value: object) -> str:
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")).hexdigest()


def _sha(value: object, label: str) -> str:
    text = str(value or "").strip().lower()
    if not _SHA256_RE.fullmatch(text):
        raise CiscoC06AcceptanceReviewError(f"{label} must be lowercase SHA-256")
    return text


def build_c06_acceptance_review_candidate(
    ingest: Mapping[str, Any],
    *,
    review_id: str,
    reviewer_ref: str,
    reviewer_attestation_sha256: str,
) -> dict[str, Any]:
    if ingest.get("schema_version") != "cisco-c06-switch-state-evidence-ingest/1":
        raise CiscoC06AcceptanceReviewError("unexpected C06 ingest schema")

    supplied = _sha(ingest.get("ingest_record_sha256"), "ingest_record_sha256")
    unsigned_ingest = dict(ingest)
    unsigned_ingest.pop("ingest_record_sha256", None)
    if not hmac.compare_digest(supplied, _canonical_sha256(unsigned_ingest)):
        raise CiscoC06AcceptanceReviewError("C06 ingest record digest mismatch")

    if ingest.get("candidate_claims_live_read") is not True:
        raise CiscoC06AcceptanceReviewError("C06 candidate must claim an observed live read")
    for field in ("repository_live_evidence_accepted", "c06_complete", "physical_device_verified", "production_write_authorized"):
        if ingest.get(field) is not False:
            raise CiscoC06AcceptanceReviewError(f"C06 ingest record crossed acceptance boundary: {field}")

    rid = str(review_id).strip()
    reviewer = str(reviewer_ref).strip()
    if not _REF_RE.fullmatch(rid) or not _REF_RE.fullmatch(reviewer):
        raise CiscoC06AcceptanceReviewError("invalid review identity")
    attestation = _sha(reviewer_attestation_sha256, "reviewer_attestation_sha256")

    result = {
        "schema_version": "cisco-c06-acceptance-review-candidate/1",
        "review_id": rid,
        "reviewer_ref": reviewer,
        "reviewer_attestation_sha256": attestation,
        "target_id": str(ingest.get("target_id", "")),
        "model": str(ingest.get("model", "")),
        "iosxe_version": str(ingest.get("iosxe_version", "")),
        "ingest_record_sha256": supplied,
        "state_digest_sha256": _sha(ingest.get("state_digest_sha256"), "state_digest_sha256"),
        "eligible_for_repository_acceptance": True,
        "repository_live_evidence_accepted": False,
        "c06_complete": False,
        "physical_device_verified": False,
        "production_write_authorized": False,
    }
    result["review_candidate_sha256"] = _canonical_sha256(result)
    return result
