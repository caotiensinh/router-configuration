"""Identity-continuity verifier for Cisco C11 physical acceptance review.

The verifier binds the immutable human-review candidate, its detached decision,
and a separately attested physical identity observation. It proves continuity
only; it cannot mark a physical device verified or complete C11 by itself.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import re
from typing import Any, Mapping

_SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
_ALLOWED_TARGET_KINDS = frozenset({"physical_router", "physical_switch"})
_VIRTUAL_FAMILIES = frozenset({"Catalyst 8000V"})


class CiscoC11IdentityContinuityError(ValueError):
    pass


def _canonical_sha256(value: object) -> str:
    return hashlib.sha256(
        json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
    ).hexdigest()


def _sha(value: object, label: str) -> str:
    text = str(value or "").strip().lower()
    if not _SHA256_RE.fullmatch(text):
        raise CiscoC11IdentityContinuityError(f"{label} must be lowercase SHA-256")
    return text


def verify_c11_identity_continuity(
    review_candidate: Mapping[str, Any],
    decision_record: Mapping[str, Any],
    identity_observation: Mapping[str, Any],
) -> dict[str, Any]:
    if review_candidate.get("schema_version") != "cisco-c11-human-review-candidate/1":
        raise CiscoC11IdentityContinuityError("unexpected C11 review candidate schema")
    review_digest = _sha(review_candidate.get("review_candidate_sha256"), "review_candidate_sha256")
    unsigned_review = dict(review_candidate)
    unsigned_review.pop("review_candidate_sha256", None)
    if not hmac.compare_digest(review_digest, _canonical_sha256(unsigned_review)):
        raise CiscoC11IdentityContinuityError("C11 review candidate digest mismatch")

    if decision_record.get("schema_version") != "cisco-c11-review-decision-candidate/1":
        raise CiscoC11IdentityContinuityError("unexpected C11 decision schema")
    decision_digest = _sha(decision_record.get("decision_record_sha256"), "decision_record_sha256")
    unsigned_decision = dict(decision_record)
    unsigned_decision.pop("decision_record_sha256", None)
    if not hmac.compare_digest(decision_digest, _canonical_sha256(unsigned_decision)):
        raise CiscoC11IdentityContinuityError("C11 decision record digest mismatch")
    if decision_record.get("review_candidate_sha256") != review_digest:
        raise CiscoC11IdentityContinuityError("C11 decision is not bound to this review candidate")
    if decision_record.get("decision") != "approve":
        raise CiscoC11IdentityContinuityError("C11 identity continuity requires an approve decision")

    if identity_observation.get("schema_version") != "cisco-c11-identity-observation/1":
        raise CiscoC11IdentityContinuityError("unexpected C11 identity observation schema")
    observation_digest = _sha(
        identity_observation.get("identity_observation_sha256"), "identity_observation_sha256"
    )
    unsigned_observation = dict(identity_observation)
    unsigned_observation.pop("identity_observation_sha256", None)
    if not hmac.compare_digest(observation_digest, _canonical_sha256(unsigned_observation)):
        raise CiscoC11IdentityContinuityError("C11 identity observation digest mismatch")

    target_kind = str(identity_observation.get("target_kind", "")).strip().lower()
    if target_kind not in _ALLOWED_TARGET_KINDS:
        raise CiscoC11IdentityContinuityError("identity observation is not a physical router or switch")
    if identity_observation.get("physical_presence_attested") is not True:
        raise CiscoC11IdentityContinuityError("physical presence attestation is required")
    if identity_observation.get("virtualization") is not False:
        raise CiscoC11IdentityContinuityError("virtual identity cannot satisfy C11 continuity")
    if identity_observation.get("production_write_authorized") is not False:
        raise CiscoC11IdentityContinuityError("identity observation cannot authorize production write")

    for field in ("target_kind", "model", "iosxe_version", "platform_family"):
        left = str(review_candidate.get(field, "")).strip()
        right = str(identity_observation.get(field, "")).strip()
        if field == "target_kind":
            left, right = left.lower(), right.lower()
        if left != right:
            raise CiscoC11IdentityContinuityError(f"C11 identity continuity mismatch: {field}")
    if str(review_candidate.get("platform_family", "")) in _VIRTUAL_FAMILIES:
        raise CiscoC11IdentityContinuityError("virtual platform family cannot satisfy C11 continuity")

    target_identity_digest = _sha(
        identity_observation.get("target_identity_digest_sha256"), "target_identity_digest_sha256"
    )
    attestation_digest = _sha(
        identity_observation.get("identity_attestation_sha256"), "identity_attestation_sha256"
    )

    result = {
        "schema_version": "cisco-c11-identity-continuity/1",
        "review_candidate_sha256": review_digest,
        "decision_record_sha256": decision_digest,
        "identity_observation_sha256": observation_digest,
        "target_identity_digest_sha256": target_identity_digest,
        "identity_attestation_sha256": attestation_digest,
        "target_kind": target_kind,
        "model": str(identity_observation.get("model", "")),
        "iosxe_version": str(identity_observation.get("iosxe_version", "")),
        "platform_family": str(identity_observation.get("platform_family", "")),
        "identity_continuity_verified": True,
        "eligible_for_physical_acceptance": True,
        "repository_physical_evidence_accepted": False,
        "physical_device_verified": False,
        "c11_complete": False,
        "production_write_authorized": False,
    }
    result["continuity_record_sha256"] = _canonical_sha256(result)
    return result
