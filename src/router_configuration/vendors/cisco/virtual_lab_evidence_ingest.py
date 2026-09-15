"""Strict ingestion boundary for Cisco C09 live virtual-lab evidence JSON.

The existing C09 validator handles semantic acceptance. This module handles the
untrusted artifact boundary first: UTF-8 decoding, size limits, duplicate keys,
closed top-level schema and sensitive-key rejection. Contract tests cannot turn
synthetic JSON into accepted repository live evidence.
"""

from __future__ import annotations

import hashlib
import json
from typing import Any, Mapping

from .validation_approval import CiscoApprovalBinding
from .virtual_lab_acceptance import build_cisco_virtual_lab_bundle

_MAX_EVIDENCE_BYTES = 128 * 1024
_ALLOWED_TOP_LEVEL_FIELDS = frozenset({
    "schema_version",
    "evidence_origin",
    "vendor",
    "os_family",
    "backend_kind",
    "backend_id",
    "target_id",
    "model",
    "iosxe_version",
    "source_sha",
    "source_run_id",
    "artifact_digest_sha256",
    "observed_identity_sha256",
    "schema_inventory_digest_sha256",
    "pre_state_sha256",
    "post_state_sha256",
    "payload_digest_sha256",
    "approval_sha256",
    "topology_sha256",
    "identity_observed",
    "lab_disposable",
    "fault_injection_lab_only",
    "lab_change_approved",
    "intended_state_verified",
    "management_survived_fault",
    "target_discarded_or_sanitized_after_run",
    "image_embedded_in_repository",
    "license_material_present",
    "hardware_present",
    "physical_hardware_claimed",
    "production_writer_available",
    "production_write_authorized",
    "scenarios",
})
_SENSITIVE_KEY_MARKERS = (
    "password",
    "passwd",
    "secret",
    "token",
    "private_key",
    "private-key",
    "community",
    "credential",
)


class CiscoVirtualLabIngestError(ValueError):
    """Raised before C09 semantics when an evidence artifact is unsafe."""


def _pairs_without_duplicates(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise CiscoVirtualLabIngestError(f"duplicate JSON key rejected: {key}")
        result[key] = value
    return result


def _reject_sensitive_keys(value: object, path: str = "$") -> None:
    if isinstance(value, Mapping):
        for key, child in value.items():
            normalized = str(key).lower().replace("_", "-")
            if any(marker.replace("_", "-") in normalized for marker in _SENSITIVE_KEY_MARKERS):
                raise CiscoVirtualLabIngestError(f"sensitive key rejected at {path}.{key}")
            _reject_sensitive_keys(child, f"{path}.{key}")
    elif isinstance(value, list):
        for index, child in enumerate(value):
            _reject_sensitive_keys(child, f"{path}[{index}]")


def ingest_cisco_virtual_lab_evidence_json(
    raw: str | bytes,
    *,
    approval: CiscoApprovalBinding,
) -> dict[str, Any]:
    """Parse, sanitize and semantically validate one candidate C09 artifact."""

    if isinstance(raw, bytes):
        raw_bytes = raw
        try:
            text = raw.decode("utf-8", errors="strict")
        except UnicodeDecodeError as exc:
            raise CiscoVirtualLabIngestError("C09 evidence must be strict UTF-8") from exc
    elif isinstance(raw, str):
        text = raw
        raw_bytes = raw.encode("utf-8")
    else:
        raise CiscoVirtualLabIngestError("C09 evidence must be JSON text or bytes")

    if not raw_bytes or len(raw_bytes) > _MAX_EVIDENCE_BYTES:
        raise CiscoVirtualLabIngestError("C09 evidence size is outside the bounded ingestion limit")

    try:
        payload = json.loads(text, object_pairs_hook=_pairs_without_duplicates)
    except CiscoVirtualLabIngestError:
        raise
    except json.JSONDecodeError as exc:
        raise CiscoVirtualLabIngestError("C09 evidence is not valid JSON") from exc

    if not isinstance(payload, Mapping):
        raise CiscoVirtualLabIngestError("C09 evidence root must be a JSON object")
    fields = set(map(str, payload.keys()))
    unknown = sorted(fields - _ALLOWED_TOP_LEVEL_FIELDS)
    missing = sorted(_ALLOWED_TOP_LEVEL_FIELDS - fields)
    if unknown:
        raise CiscoVirtualLabIngestError("unknown C09 top-level fields: " + ", ".join(unknown))
    if missing:
        raise CiscoVirtualLabIngestError("missing C09 top-level fields: " + ", ".join(missing))

    _reject_sensitive_keys(payload)
    bundle = build_cisco_virtual_lab_bundle(payload, approval=approval)
    result = {
        "schema_version": "cisco-c09-live-evidence-ingest/1",
        "source_payload_sha256": hashlib.sha256(raw_bytes).hexdigest(),
        "validated_bundle_sha256": bundle["bundle_sha256"],
        "source_sha": bundle["source_sha"],
        "source_run_id": bundle["source_run_id"],
        "target_id": bundle["target_id"],
        "model": bundle["model"],
        "iosxe_version": bundle["iosxe_version"],
        "candidate_bundle_claims_live_virtual_iosxe": bundle["live_virtual_iosxe_observed"],
        "candidate_bundle_claims_c09_complete": bundle["c09_complete"],
        "repository_live_evidence_accepted": False,
        "repository_c09_complete": False,
        "physical_hardware_claimed": False,
        "production_writer_available": False,
        "production_write_authorized": False,
    }
    result["ingest_record_sha256"] = hashlib.sha256(
        json.dumps(result, sort_keys=True, separators=(",", ":")).encode("utf-8")
    ).hexdigest()
    return result
