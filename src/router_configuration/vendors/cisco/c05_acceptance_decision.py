"""Final repository decision binding for reviewed Cisco C05 router-state evidence.

The function consumes the immutable C05 live-state ingest candidate and records
an explicit accept/reject decision. Acceptance completes only the repository C05
live-evidence gate for that exact candidate; it never claims physical-device
verification or production-write authority.
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


class CiscoC05AcceptanceDecisionError(ValueError):
    """Raised when a C05 repository acceptance decision fails closed."""


def _canonical_sha256(value: object) -> str:
    return hashlib.sha256(
        json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
    ).hexdigest()


def _sha(value: object, label: str) -> str:
    text = str(value or "").strip().lower()
    if not _SHA256_RE.fullmatch(text):
        raise CiscoC05AcceptanceDecisionError(f"{label} must be lowercase SHA-256")
    return text


def bind_c05_repository_decision(
    ingest_candidate: Mapping[str, Any],
    *,
    decision_id: str,
    authority_ref: str,
    authority_attestation_sha256: str,
    decision: str,
) -> dict[str, Any]:
    """Bind an explicit repository decision to one immutable C05 ingest record."""

    if ingest_candidate.get("schema_version") != "cisco-c05-live-state-ingest/1":
        raise CiscoC05AcceptanceDecisionError("unexpected C05 ingest schema")

    supplied = _sha(ingest_candidate.get("ingest_record_sha256"), "ingest_record_sha256")
    unsigned = dict(ingest_candidate)
    unsigned.pop("ingest_record_sha256", None)
    if not hmac.compare_digest(supplied, _canonical_sha256(unsigned)):
        raise CiscoC05AcceptanceDecisionError("C05 ingest record digest mismatch")

    source_sha = str(ingest_candidate.get("source_sha", "")).strip().lower()
    if not _SHA40_RE.fullmatch(source_sha):
        raise CiscoC05AcceptanceDecisionError("C05 source_sha must be a pinned Git SHA")

    if ingest_candidate.get("candidate_claims_live_state") is not True:
        raise CiscoC05AcceptanceDecisionError("C05 candidate does not claim observed live state")
    if ingest_candidate.get("eligible_for_repository_review") is not True:
        raise CiscoC05AcceptanceDecisionError("C05 candidate is not eligible for repository review")

    for field in (
        "repository_live_evidence_accepted",
        "repository_c05_complete",
        "physical_device_verified",
        "production_write_authorized",
    ):
        if ingest_candidate.get(field) is not False:
            raise CiscoC05AcceptanceDecisionError(f"C05 ingest candidate crossed acceptance boundary: {field}")

    run_id = str(ingest_candidate.get("run_id", "")).strip()
    if not _REF_RE.fullmatch(run_id):
        raise CiscoC05AcceptanceDecisionError("invalid C05 run_id")
    transport = str(ingest_candidate.get("transport", "")).strip().upper()
    if transport not in {"NETCONF_READONLY", "RESTCONF_GET"}:
        raise CiscoC05AcceptanceDecisionError("unsupported C05 read-only transport")

    did = str(decision_id).strip()
    authority = str(authority_ref).strip()
    if not _REF_RE.fullmatch(did) or not _REF_RE.fullmatch(authority):
        raise CiscoC05AcceptanceDecisionError("invalid C05 decision identity")
    normalized_decision = str(decision).strip().lower()
    if normalized_decision not in _DECISIONS:
        raise CiscoC05AcceptanceDecisionError("unsupported C05 decision")
    attestation = _sha(authority_attestation_sha256, "authority_attestation_sha256")

    accepted = normalized_decision == "accept"
    result = {
        "schema_version": "cisco-c05-repository-acceptance-decision/1",
        "decision_id": did,
        "authority_ref": authority,
        "authority_attestation_sha256": attestation,
        "decision": normalized_decision,
        "ingest_record_sha256": supplied,
        "source_sha": source_sha,
        "run_id": run_id,
        "transport": transport,
        "raw_live_artifact_sha256": _sha(
            ingest_candidate.get("raw_live_artifact_sha256"), "raw_live_artifact_sha256"
        ),
        "collector_attestation_sha256": _sha(
            ingest_candidate.get("collector_attestation_sha256"), "collector_attestation_sha256"
        ),
        "integrity_record_sha256": _sha(
            ingest_candidate.get("integrity_record_sha256"), "integrity_record_sha256"
        ),
        "state_digest_sha256": _sha(
            ingest_candidate.get("state_digest_sha256"), "state_digest_sha256"
        ),
        "schema_inventory_digest_sha256": _sha(
            ingest_candidate.get("schema_inventory_digest_sha256"), "schema_inventory_digest_sha256"
        ),
        "model": str(ingest_candidate.get("model", "")).strip(),
        "iosxe_version": str(ingest_candidate.get("iosxe_version", "")).strip(),
        "repository_live_evidence_accepted": accepted,
        "repository_c05_complete": accepted,
        "physical_device_verified": False,
        "production_write_authorized": False,
    }
    if not result["model"] or not result["iosxe_version"]:
        raise CiscoC05AcceptanceDecisionError("C05 candidate lacks platform identity")

    result["decision_record_sha256"] = _canonical_sha256(result)
    return result
