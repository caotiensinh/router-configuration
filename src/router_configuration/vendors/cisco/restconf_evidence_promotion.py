"""Fail-closed promotion check for Cisco C04 live RESTCONF evidence.

This verifier checks a successful live RESTCONF probe artifact before it can be
considered by repository acceptance logic. It verifies digest integrity, GET-only
scope, TLS/certificate invariants, redirect rejection, platform binding and the
no-write boundary. Passing this verifier still does not complete C04 by itself.
"""

from __future__ import annotations

import hashlib
import json
import re
from typing import Any, Mapping

_SHA40 = re.compile(r"^[0-9a-f]{40}$")
_SHA256 = re.compile(r"^[0-9a-f]{64}$")
_REQUIRED_DIGESTS = (
    "knowledge_digest_sha256",
    "target_host_digest_sha256",
    "restconf_root_digest_sha256",
    "capability_inventory_digest_sha256",
    "identity_digest_sha256",
    "hostname_digest_sha256",
    "peer_certificate_sha256",
    "platform_evidence_digest_sha256",
)


class CiscoRestconfPromotionError(ValueError):
    """Raised when C04 evidence is not safe to promote for repository review."""


def _canonical_sha256(value: object) -> str:
    raw = json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True)
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()


def verify_c04_live_evidence(evidence: Mapping[str, Any]) -> dict[str, Any]:
    """Verify one live C04 artifact without awarding repository completion."""

    if not isinstance(evidence, Mapping):
        raise CiscoRestconfPromotionError("C04 evidence must be an object")
    if evidence.get("schema_version") != "cisco-c04-live-restconf-evidence/2":
        raise CiscoRestconfPromotionError("unsupported C04 evidence schema")
    source_sha = str(evidence.get("source_sha", "")).strip().lower()
    if not _SHA40.fullmatch(source_sha):
        raise CiscoRestconfPromotionError("C04 source_sha must be a pinned Git SHA")

    supplied_digest = str(evidence.get("evidence_digest_sha256", "")).strip().lower()
    if not _SHA256.fullmatch(supplied_digest):
        raise CiscoRestconfPromotionError("C04 evidence digest is missing or invalid")
    unsigned = {key: value for key, value in evidence.items() if key != "evidence_digest_sha256"}
    if _canonical_sha256(unsigned) != supplied_digest:
        raise CiscoRestconfPromotionError("C04 evidence digest mismatch")

    if evidence.get("result") != "live_readonly_admitted":
        raise CiscoRestconfPromotionError("C04 result is not live_readonly_admitted")
    if evidence.get("live_target_observed") is not True or evidence.get("c04_complete") is not True:
        raise CiscoRestconfPromotionError("C04 live-success invariants are missing")
    if evidence.get("request_method_scope") != ["GET"]:
        raise CiscoRestconfPromotionError("C04 must remain GET-only")
    if evidence.get("tls_certificate_verification_required") is not True:
        raise CiscoRestconfPromotionError("C04 requires TLS certificate verification")
    if evidence.get("redirect_following_allowed") is not False:
        raise CiscoRestconfPromotionError("C04 redirects must remain disabled")
    if evidence.get("credentials_persisted") is not False:
        raise CiscoRestconfPromotionError("C04 credentials must not be persisted")
    if evidence.get("platform_evidence_bound") is not True:
        raise CiscoRestconfPromotionError("C04 platform evidence is not bound")
    for key in ("production_write_authorized", "physical_device_verified", "write_operations_performed"):
        if evidence.get(key) is not False:
            raise CiscoRestconfPromotionError(f"C04 safety boundary violated: {key}")
    for key in _REQUIRED_DIGESTS:
        value = str(evidence.get(key, "")).strip().lower()
        if not _SHA256.fullmatch(value):
            raise CiscoRestconfPromotionError(f"missing or invalid C04 digest: {key}")

    record = {
        "schema_version": "cisco-c04-repository-review/1",
        "source_sha": source_sha,
        "source_evidence_digest_sha256": supplied_digest,
        "candidate_live_claim_valid": True,
        "get_only_verified": True,
        "tls_verified": True,
        "redirects_disabled": True,
        "platform_binding_verified": True,
        "repository_evidence_accepted": False,
        "repository_c04_complete": False,
        "production_write_authorized": False,
        "physical_device_verified": False,
    }
    record["review_record_sha256"] = _canonical_sha256(record)
    return record
