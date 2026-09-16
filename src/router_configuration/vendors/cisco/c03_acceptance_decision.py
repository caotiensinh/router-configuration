"""Repository acceptance decision binding for sanitized Cisco C03 evidence.

This module binds a detached human decision to the exact sanitized live NETCONF
artifact produced by the C03 workflow. It can record repository acceptance of
that evidence but never grants physical-device or production-write authority.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import re
from typing import Any, Mapping

_SHA40_RE = re.compile(r"^[0-9a-f]{40}$")
_SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
_REF_RE = re.compile(r"^[A-Za-z0-9_.:@/-]{1,128}$")
_DECISIONS = frozenset({"accept", "reject"})
_REQUIRED_DIGESTS = (
    "target_host_digest_sha256",
    "hostname_digest_sha256",
    "hostkey_pin_digest_sha256",
    "capability_digest_sha256",
    "schema_inventory_digest_sha256",
    "platform_component_digest_sha256",
    "interface_digest_sha256",
)
_FORBIDDEN_KEYS = frozenset({"target_host", "hostname", "session_id", "username", "password", "authorization"})


class CiscoC03AcceptanceDecisionError(ValueError):
    """Raised when C03 repository acceptance evidence fails closed."""


def _canonical_sha256(value: object) -> str:
    return hashlib.sha256(
        json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
    ).hexdigest()


def _sha(value: object, label: str) -> str:
    text = str(value or "").strip().lower()
    if not _SHA256_RE.fullmatch(text):
        raise CiscoC03AcceptanceDecisionError(f"{label} must be lowercase SHA-256")
    return text


def bind_c03_repository_decision(
    evidence: Mapping[str, Any],
    *,
    artifact_sha256: str,
    decision_id: str,
    authority_ref: str,
    authority_attestation_sha256: str,
    decision: str,
) -> dict[str, Any]:
    if evidence.get("schema_version") != "cisco-c03-live-evidence/1":
        raise CiscoC03AcceptanceDecisionError("unexpected C03 live evidence schema")

    artifact_digest = _sha(artifact_sha256, "artifact_sha256")
    if not hmac.compare_digest(artifact_digest, _canonical_sha256(dict(evidence))):
        raise CiscoC03AcceptanceDecisionError("C03 sanitized artifact digest mismatch")

    source_sha = str(evidence.get("source_sha", "")).strip().lower()
    if not _SHA40_RE.fullmatch(source_sha):
        raise CiscoC03AcceptanceDecisionError("C03 source_sha must be a pinned Git SHA")

    if evidence.get("stage") != "live_readonly_verified":
        raise CiscoC03AcceptanceDecisionError("C03 artifact is not a verified live read-only run")
    if evidence.get("live_target_observed") is not True:
        raise CiscoC03AcceptanceDecisionError("C03 artifact lacks live target observation")
    if evidence.get("hostkey_verified") is not True:
        raise CiscoC03AcceptanceDecisionError("C03 artifact lacks SSH host-key verification")
    if evidence.get("c03_complete") is not True:
        raise CiscoC03AcceptanceDecisionError("C03 live probe did not complete")
    for field in ("write_operations_performed", "production_write_authorized", "physical_device_verified"):
        if evidence.get(field) is not False:
            raise CiscoC03AcceptanceDecisionError(f"C03 safety boundary violated: {field}")
    if _FORBIDDEN_KEYS.intersection(evidence):
        raise CiscoC03AcceptanceDecisionError("C03 sanitized artifact contains forbidden target/session metadata")
    for field in _REQUIRED_DIGESTS:
        _sha(evidence.get(field), field)

    did = str(decision_id).strip()
    authority = str(authority_ref).strip()
    if not _REF_RE.fullmatch(did) or not _REF_RE.fullmatch(authority):
        raise CiscoC03AcceptanceDecisionError("invalid C03 decision identity")
    normalized_decision = str(decision).strip().lower()
    if normalized_decision not in _DECISIONS:
        raise CiscoC03AcceptanceDecisionError("unsupported C03 decision")
    attestation = _sha(authority_attestation_sha256, "authority_attestation_sha256")

    accepted = normalized_decision == "accept"
    result = {
        "schema_version": "cisco-c03-repository-acceptance-decision/1",
        "source_sha": source_sha,
        "artifact_sha256": artifact_digest,
        "decision_id": did,
        "authority_ref": authority,
        "authority_attestation_sha256": attestation,
        "decision": normalized_decision,
        "repository_live_evidence_accepted": accepted,
        "repository_c03_complete": accepted,
        "physical_device_verified": False,
        "production_write_authorized": False,
    }
    result["decision_record_sha256"] = _canonical_sha256(result)
    return result
