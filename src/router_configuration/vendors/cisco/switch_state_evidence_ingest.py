"""Evidence-ingest boundary for Cisco C06 normalized switch state.

This layer binds a normalized-state contract artifact to sanitized run provenance.
It does not read a device, cannot manufacture live evidence, and never promotes a
candidate artifact into accepted C06 completion.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import re
from typing import Any, Mapping

from .switch_state import SwitchNormalizedState, switch_state_catalog_digest

_SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
_GIT_SHA_RE = re.compile(r"^[0-9a-f]{40}$")
_TARGET_RE = re.compile(r"^[A-Za-z0-9_.:/-]{1,128}$")
_RUN_RE = re.compile(r"^[A-Za-z0-9_.:-]{1,96}$")
_ALLOWED_TRANSPORTS = frozenset({"netconf", "restconf"})


class CiscoSwitchStateEvidenceError(ValueError):
    """Raised when a C06 evidence candidate fails closed."""


def _sha(value: object, field: str) -> str:
    text = str(value or "").strip().lower()
    if not _SHA256_RE.fullmatch(text):
        raise CiscoSwitchStateEvidenceError(f"{field} must be lowercase SHA-256")
    return text


def ingest_switch_state_evidence(
    payload: Mapping[str, Any],
    *,
    state: SwitchNormalizedState,
) -> dict[str, Any]:
    if payload.get("schema_version") != "cisco-c06-live-switch-state-evidence/1":
        raise CiscoSwitchStateEvidenceError("unexpected C06 evidence schema")

    target_id = str(payload.get("target_id", "")).strip()
    if not _TARGET_RE.fullmatch(target_id):
        raise CiscoSwitchStateEvidenceError("invalid target_id")
    source_sha = str(payload.get("source_sha", "")).strip().lower()
    if not _GIT_SHA_RE.fullmatch(source_sha):
        raise CiscoSwitchStateEvidenceError("source_sha must be a 40-character Git SHA")
    source_run_id = str(payload.get("source_run_id", "")).strip()
    if not _RUN_RE.fullmatch(source_run_id):
        raise CiscoSwitchStateEvidenceError("invalid source_run_id")
    transport = str(payload.get("transport", "")).strip().lower()
    if transport not in _ALLOWED_TRANSPORTS:
        raise CiscoSwitchStateEvidenceError("unsupported C06 read-only transport")

    if payload.get("evidence_origin") != "live_iosxe_switch_readonly":
        raise CiscoSwitchStateEvidenceError("C06 evidence origin must identify a live IOS XE switch read")
    if payload.get("live_read_observed") is not True:
        raise CiscoSwitchStateEvidenceError("live_read_observed must be true")
    if payload.get("read_only") is not True or payload.get("write_attempted") is not False:
        raise CiscoSwitchStateEvidenceError("C06 evidence must remain read-only with no write attempt")
    if payload.get("synthetic_fixture") is not False:
        raise CiscoSwitchStateEvidenceError("synthetic fixture cannot enter C06 live evidence ingestion")
    for field in ("repository_live_evidence_accepted", "c06_complete", "physical_device_verified", "production_write_authorized"):
        if payload.get(field) is not False:
            raise CiscoSwitchStateEvidenceError(f"C06 artifact cannot self-promote: {field}")

    if not state.trunk_state_verified or not state.c06_contract_complete:
        raise CiscoSwitchStateEvidenceError("normalized state must satisfy the C06 contract before evidence ingestion")
    if state.c06_complete or state.production_write_authorized or state.physical_device_verified:
        raise CiscoSwitchStateEvidenceError("normalized-state input crossed the pre-acceptance safety boundary")

    state_digest = _sha(payload.get("state_digest_sha256"), "state_digest_sha256")
    schema_digest = _sha(payload.get("schema_inventory_digest_sha256"), "schema_inventory_digest_sha256")
    catalog_digest = _sha(payload.get("catalog_digest_sha256"), "catalog_digest_sha256")
    if not hmac.compare_digest(state_digest, state.state_digest_sha256):
        raise CiscoSwitchStateEvidenceError("state digest differs from normalized-state artifact")
    if not hmac.compare_digest(schema_digest, state.schema_inventory_digest_sha256):
        raise CiscoSwitchStateEvidenceError("schema inventory digest differs from normalized-state artifact")
    expected_catalog = switch_state_catalog_digest()
    if not hmac.compare_digest(catalog_digest, state.catalog_digest_sha256) or not hmac.compare_digest(catalog_digest, expected_catalog):
        raise CiscoSwitchStateEvidenceError("switch-state catalog digest is stale or different")

    result = {
        "schema_version": "cisco-c06-switch-state-evidence-ingest/1",
        "target_id": target_id,
        "model": state.model,
        "iosxe_version": state.iosxe_version,
        "platform_family": state.platform_family,
        "source_sha": source_sha,
        "source_run_id": source_run_id,
        "transport": transport,
        "state_digest_sha256": state_digest,
        "schema_inventory_digest_sha256": schema_digest,
        "catalog_digest_sha256": catalog_digest,
        "candidate_claims_live_read": True,
        "repository_live_evidence_accepted": False,
        "c06_complete": False,
        "physical_device_verified": False,
        "production_write_authorized": False,
    }
    result["ingest_record_sha256"] = hashlib.sha256(
        json.dumps(result, sort_keys=True, separators=(",", ":")).encode("utf-8")
    ).hexdigest()
    return result
