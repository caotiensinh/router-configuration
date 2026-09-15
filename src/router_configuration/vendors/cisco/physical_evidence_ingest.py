"""Strict JSON ingestion boundary for Cisco C11 physical read-only evidence.

The parser rejects duplicate keys, unknown fields, sensitive metadata, virtual
platforms and any attempt to self-promote a candidate claim into accepted C11
evidence. Repository acceptance remains a separate human review step.
"""

from __future__ import annotations

import hashlib
import json
from typing import Any, Mapping

from .physical_acceptance import validate_physical_readonly_claim

_MAX_BYTES = 64 * 1024
_ALLOWED_FIELDS = frozenset({
    "schema_version",
    "target_kind",
    "model",
    "iosxe_version",
    "transport",
    "source_sha",
    "source_run_id",
    "schema_inventory_digest_sha256",
    "observation_digest_sha256",
    "target_identity_digest_sha256",
    "human_attestation_digest_sha256",
    "evidence_origin",
    "human_attested",
    "read_only",
    "write_attempted",
    "virtualization",
    "repository_physical_evidence_accepted",
    "c11_complete",
    "physical_device_verified",
    "production_write_authorized",
})
_SENSITIVE_MARKERS = ("password", "secret", "token", "private-key", "private_key", "community", "credential")


class CiscoPhysicalEvidenceIngestError(ValueError):
    """Raised before C11 semantic validation when an artifact is unsafe."""


def _pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise CiscoPhysicalEvidenceIngestError(f"duplicate JSON key rejected: {key}")
        result[key] = value
    return result


def _reject_sensitive(value: object, path: str = "$") -> None:
    if isinstance(value, Mapping):
        for key, child in value.items():
            normalized = str(key).lower().replace("_", "-")
            if any(marker.replace("_", "-") in normalized for marker in _SENSITIVE_MARKERS):
                raise CiscoPhysicalEvidenceIngestError(f"sensitive key rejected at {path}.{key}")
            _reject_sensitive(child, f"{path}.{key}")
    elif isinstance(value, list):
        for index, child in enumerate(value):
            _reject_sensitive(child, f"{path}[{index}]")


def ingest_physical_readonly_evidence_json(raw: str | bytes) -> dict[str, Any]:
    if isinstance(raw, bytes):
        raw_bytes = raw
        try:
            text = raw.decode("utf-8", errors="strict")
        except UnicodeDecodeError as exc:
            raise CiscoPhysicalEvidenceIngestError("C11 evidence must be strict UTF-8") from exc
    elif isinstance(raw, str):
        text = raw
        raw_bytes = raw.encode("utf-8")
    else:
        raise CiscoPhysicalEvidenceIngestError("C11 evidence must be JSON text or bytes")

    if not raw_bytes or len(raw_bytes) > _MAX_BYTES:
        raise CiscoPhysicalEvidenceIngestError("C11 evidence size is outside the bounded ingestion limit")

    try:
        payload = json.loads(text, object_pairs_hook=_pairs)
    except CiscoPhysicalEvidenceIngestError:
        raise
    except json.JSONDecodeError as exc:
        raise CiscoPhysicalEvidenceIngestError("C11 evidence is not valid JSON") from exc

    if not isinstance(payload, Mapping):
        raise CiscoPhysicalEvidenceIngestError("C11 evidence root must be an object")
    fields = set(map(str, payload.keys()))
    unknown = sorted(fields - _ALLOWED_FIELDS)
    missing = sorted(_ALLOWED_FIELDS - fields)
    if unknown:
        raise CiscoPhysicalEvidenceIngestError("unknown C11 top-level fields: " + ", ".join(unknown))
    if missing:
        raise CiscoPhysicalEvidenceIngestError("missing C11 top-level fields: " + ", ".join(missing))

    _reject_sensitive(payload)
    for field in ("repository_physical_evidence_accepted", "c11_complete", "physical_device_verified", "production_write_authorized"):
        if payload.get(field) is not False:
            raise CiscoPhysicalEvidenceIngestError(f"C11 artifact cannot self-promote: {field}")

    source_run_id = str(payload.get("source_run_id", "")).strip()
    if not source_run_id or len(source_run_id) > 96 or any(ord(c) < 33 or ord(c) > 126 for c in source_run_id):
        raise CiscoPhysicalEvidenceIngestError("invalid source_run_id")

    claim = validate_physical_readonly_claim(
        target_kind=str(payload["target_kind"]),
        model=str(payload["model"]),
        iosxe_version=str(payload["iosxe_version"]),
        transport=str(payload["transport"]),
        source_sha=str(payload["source_sha"]),
        schema_inventory_digest_sha256=str(payload["schema_inventory_digest_sha256"]),
        observation_digest_sha256=str(payload["observation_digest_sha256"]),
        target_identity_digest_sha256=str(payload["target_identity_digest_sha256"]),
        human_attestation_digest_sha256=str(payload["human_attestation_digest_sha256"]),
        evidence_origin=str(payload["evidence_origin"]),
        human_attested=payload["human_attested"] is True,
        read_only=payload["read_only"] is True,
        write_attempted=payload["write_attempted"] is True,
        virtualization=payload["virtualization"] is True,
    )
    result = {
        "schema_version": "cisco-c11-physical-evidence-ingest/1",
        "source_payload_sha256": hashlib.sha256(raw_bytes).hexdigest(),
        "source_run_id": source_run_id,
        "target_kind": claim.target_kind,
        "model": claim.model,
        "iosxe_version": claim.iosxe_version,
        "platform_family": claim.platform_family,
        "role": claim.role,
        "transport": claim.transport,
        "claim_contract_digest_sha256": claim.contract_digest_sha256,
        "eligible_for_human_acceptance": claim.eligible_for_human_acceptance,
        "repository_physical_evidence_accepted": False,
        "c11_complete": False,
        "physical_device_verified": False,
        "production_write_authorized": False,
    }
    result["ingest_record_sha256"] = hashlib.sha256(
        json.dumps(result, sort_keys=True, separators=(",", ":")).encode("utf-8")
    ).hexdigest()
    return result
