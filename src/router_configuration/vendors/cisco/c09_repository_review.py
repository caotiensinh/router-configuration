"""Repository-review candidate boundary for Cisco C09 live virtual evidence.

The module revalidates an ingested C09 artifact and binds it to a detached human
review attestation. It cannot itself accept the evidence or complete C09.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import re
from typing import Any, Mapping

_SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
_REF_RE = re.compile(r"^[A-Za-z0-9_.:@/-]{1,128}$")


class CiscoC09RepositoryReviewError(ValueError):
    """Raised when a C09 repository-review candidate fails closed."""


def _canonical_sha256(value: object) -> str:
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")).hexdigest()


def _sha(value: object, label: str) -> str:
    text = str(value or "").strip().lower()
    if not _SHA256_RE.fullmatch(text):
        raise CiscoC09RepositoryReviewError(f"{label} must be lowercase SHA-256")
    return text


def build_c09_repository_review_candidate(
    ingest: Mapping[str, Any],
    *,
    review_id: str,
    reviewer_ref: str,
    reviewer_attestation_sha256: str,
) -> dict[str, Any]:
    if ingest.get("schema_version") != "cisco-c09-live-evidence-ingest/1":
        raise CiscoC09RepositoryReviewError("unexpected C09 ingest schema")

    supplied = _sha(ingest.get("ingest_record_sha256"), "ingest_record_sha256")
    unsigned = dict(ingest)
    unsigned.pop("ingest_record_sha256", None)
    if not hmac.compare_digest(supplied, _canonical_sha256(unsigned)):
        raise CiscoC09RepositoryReviewError("C09 ingest record digest mismatch")

    if ingest.get("candidate_bundle_claims_live_virtual_iosxe") is not True:
        raise CiscoC09RepositoryReviewError("C09 candidate lacks live virtual IOS XE claim")
    if ingest.get("candidate_bundle_claims_c09_complete") is not True:
        raise CiscoC09RepositoryReviewError("C09 validated bundle did not satisfy the semantic contract")
    for field in ("repository_live_evidence_accepted", "repository_c09_complete", "physical_hardware_claimed", "production_writer_available", "production_write_authorized"):
        if ingest.get(field) is not False:
            raise CiscoC09RepositoryReviewError(f"C09 ingest record crossed repository boundary: {field}")

    rid = str(review_id).strip()
    reviewer = str(reviewer_ref).strip()
    if not _REF_RE.fullmatch(rid) or not _REF_RE.fullmatch(reviewer):
        raise CiscoC09RepositoryReviewError("invalid C09 review identity")
    attestation = _sha(reviewer_attestation_sha256, "reviewer_attestation_sha256")

    result = {
        "schema_version": "cisco-c09-repository-review-candidate/1",
        "review_id": rid,
        "reviewer_ref": reviewer,
        "reviewer_attestation_sha256": attestation,
        "target_id": str(ingest.get("target_id", "")),
        "model": str(ingest.get("model", "")),
        "iosxe_version": str(ingest.get("iosxe_version", "")),
        "ingest_record_sha256": supplied,
        "validated_bundle_sha256": _sha(ingest.get("validated_bundle_sha256"), "validated_bundle_sha256"),
        "eligible_for_repository_acceptance": True,
        "repository_live_evidence_accepted": False,
        "c09_complete": False,
        "physical_hardware_claimed": False,
        "production_writer_available": False,
        "production_write_authorized": False,
    }
    result["review_candidate_sha256"] = _canonical_sha256(result)
    return result
