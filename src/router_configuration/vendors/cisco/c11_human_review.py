"""Human-review candidate boundary for Cisco C11 physical evidence.

This module verifies the C11 physical-evidence ingest record and binds a detached
review attestation. It cannot mark a physical device verified or complete C11.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import re
from typing import Any, Mapping

_SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
_REF_RE = re.compile(r"^[A-Za-z0-9_.:@/-]{1,128}$")


class CiscoC11HumanReviewError(ValueError):
    """Raised when a C11 human-review candidate fails closed."""


def _canonical_sha256(value: object) -> str:
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")).hexdigest()


def _sha(value: object, label: str) -> str:
    text = str(value or "").strip().lower()
    if not _SHA256_RE.fullmatch(text):
        raise CiscoC11HumanReviewError(f"{label} must be lowercase SHA-256")
    return text


def build_c11_human_review_candidate(
    ingest: Mapping[str, Any],
    *,
    review_id: str,
    reviewer_ref: str,
    reviewer_attestation_sha256: str,
) -> dict[str, Any]:
    if ingest.get("schema_version") != "cisco-c11-physical-evidence-ingest/1":
        raise CiscoC11HumanReviewError("unexpected C11 ingest schema")

    supplied = _sha(ingest.get("ingest_record_sha256"), "ingest_record_sha256")
    unsigned = dict(ingest)
    unsigned.pop("ingest_record_sha256", None)
    if not hmac.compare_digest(supplied, _canonical_sha256(unsigned)):
        raise CiscoC11HumanReviewError("C11 ingest record digest mismatch")

    if ingest.get("eligible_for_human_acceptance") is not True:
        raise CiscoC11HumanReviewError("C11 ingest record is not eligible for human acceptance")
    for field in ("repository_physical_evidence_accepted", "c11_complete", "physical_device_verified", "production_write_authorized"):
        if ingest.get(field) is not False:
            raise CiscoC11HumanReviewError(f"C11 ingest record crossed acceptance boundary: {field}")

    rid = str(review_id).strip()
    reviewer = str(reviewer_ref).strip()
    if not _REF_RE.fullmatch(rid) or not _REF_RE.fullmatch(reviewer):
        raise CiscoC11HumanReviewError("invalid C11 review identity")
    attestation = _sha(reviewer_attestation_sha256, "reviewer_attestation_sha256")

    result = {
        "schema_version": "cisco-c11-human-review-candidate/1",
        "review_id": rid,
        "reviewer_ref": reviewer,
        "reviewer_attestation_sha256": attestation,
        "target_kind": str(ingest.get("target_kind", "")),
        "model": str(ingest.get("model", "")),
        "iosxe_version": str(ingest.get("iosxe_version", "")),
        "platform_family": str(ingest.get("platform_family", "")),
        "ingest_record_sha256": supplied,
        "claim_contract_digest_sha256": _sha(ingest.get("claim_contract_digest_sha256"), "claim_contract_digest_sha256"),
        "eligible_for_repository_acceptance": True,
        "repository_physical_evidence_accepted": False,
        "c11_complete": False,
        "physical_device_verified": False,
        "production_write_authorized": False,
    }
    result["review_candidate_sha256"] = _canonical_sha256(result)
    return result
