"""Fail-closed ingest boundary for live Cisco C05 normalized router state.

The function binds an integrity-checked normalized state to an immutable raw
live-artifact digest, source commit, run identity, and collector attestation. It
creates a review candidate only; repository completion and write authority stay
false until a later acceptance decision consumes real evidence.
"""

from __future__ import annotations

import hashlib
import json
import re
from typing import Any

from .router_state import RouterNormalizedState
from .router_state_integrity import verify_router_state_integrity

_SHA40_RE = re.compile(r"^[0-9a-f]{40}$")
_SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
_REF_RE = re.compile(r"^[A-Za-z0-9_.:@/-]{1,128}$")
_TRANSPORTS = frozenset({"NETCONF_READONLY", "RESTCONF_GET"})


class CiscoC05LiveStateIngestError(ValueError):
    pass


def _canonical_sha256(value: object) -> str:
    return hashlib.sha256(
        json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
    ).hexdigest()


def _sha(value: object, label: str) -> str:
    text = str(value or "").strip().lower()
    if not _SHA256_RE.fullmatch(text):
        raise CiscoC05LiveStateIngestError(f"{label} must be lowercase SHA-256")
    return text


def ingest_c05_live_state_candidate(
    state: RouterNormalizedState,
    *,
    source_sha: str,
    run_id: str,
    transport: str,
    raw_live_artifact_sha256: str,
    collector_attestation_sha256: str,
    live_target_observed: bool,
) -> dict[str, Any]:
    source = str(source_sha).strip().lower()
    if not _SHA40_RE.fullmatch(source):
        raise CiscoC05LiveStateIngestError("source_sha must be a pinned Git SHA")
    run = str(run_id).strip()
    if not _REF_RE.fullmatch(run):
        raise CiscoC05LiveStateIngestError("invalid run_id")
    normalized_transport = str(transport).strip().upper()
    if normalized_transport not in _TRANSPORTS:
        raise CiscoC05LiveStateIngestError("unsupported C05 read-only transport")
    if live_target_observed is not True:
        raise CiscoC05LiveStateIngestError("C05 ingest requires an observed live target")

    raw_digest = _sha(raw_live_artifact_sha256, "raw_live_artifact_sha256")
    collector_digest = _sha(collector_attestation_sha256, "collector_attestation_sha256")
    integrity = verify_router_state_integrity(state)
    integrity_digest = _sha(integrity.get("integrity_record_sha256"), "integrity_record_sha256")

    result = {
        "schema_version": "cisco-c05-live-state-ingest/1",
        "source_sha": source,
        "run_id": run,
        "transport": normalized_transport,
        "raw_live_artifact_sha256": raw_digest,
        "collector_attestation_sha256": collector_digest,
        "integrity_record_sha256": integrity_digest,
        "state_digest_sha256": state.state_digest_sha256,
        "schema_inventory_digest_sha256": state.schema_inventory_digest_sha256,
        "model": state.model,
        "iosxe_version": state.iosxe_version,
        "candidate_claims_live_state": True,
        "eligible_for_repository_review": True,
        "repository_live_evidence_accepted": False,
        "repository_c05_complete": False,
        "physical_device_verified": False,
        "production_write_authorized": False,
    }
    result["ingest_record_sha256"] = _canonical_sha256(result)
    return result
