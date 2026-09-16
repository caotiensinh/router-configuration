"""Fail-closed request contract for Cisco read-only acceptance dispatches.

The contract is intentionally limited to live read-only C03/C04 workflows. It
binds a request to one target branch and one exact expected source SHA. It never
grants write, physical-device, or production authority.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import re
from typing import Any, Mapping

_SCHEMA = "cisco-acceptance-dispatch-request/1"
_SHA40 = re.compile(r"^[0-9a-f]{40}$")
_SHA256 = re.compile(r"^[0-9a-f]{64}$")
_REF = re.compile(r"^[A-Za-z0-9_.:@/-]{1,160}$")
_TARGET_REF = re.compile(r"^feat/cisco-iosxe-router-switch-domain-[A-Za-z0-9._-]+$")
_ALLOWED_STAGES = {
    "c03": "cisco-netconf-live-readonly.yml",
    "c04": "cisco-restconf-live-readonly.yml",
}
_REQUIRED_KEYS = frozenset(
    {
        "schema_version",
        "request_id",
        "stage",
        "target_ref",
        "expected_source_sha",
        "requested_by_ref",
        "requested_by_attestation_sha256",
        "read_only_required",
        "production_write_authorized",
        "request_sha256",
    }
)


class CiscoAcceptanceDispatchRequestError(ValueError):
    """Raised when a dispatch request violates the acceptance boundary."""


def _canonical_sha256(value: object) -> str:
    raw = json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()


def _sha256(value: object, label: str) -> str:
    text = str(value or "").strip().lower()
    if not _SHA256.fullmatch(text):
        raise CiscoAcceptanceDispatchRequestError(f"{label} must be lowercase SHA-256")
    return text


def build_dispatch_request(
    *,
    request_id: str,
    stage: str,
    target_ref: str,
    expected_source_sha: str,
    requested_by_ref: str,
    requested_by_attestation_sha256: str,
) -> dict[str, Any]:
    payload = {
        "schema_version": _SCHEMA,
        "request_id": str(request_id).strip(),
        "stage": str(stage).strip().lower(),
        "target_ref": str(target_ref).strip(),
        "expected_source_sha": str(expected_source_sha).strip().lower(),
        "requested_by_ref": str(requested_by_ref).strip(),
        "requested_by_attestation_sha256": str(requested_by_attestation_sha256).strip().lower(),
        "read_only_required": True,
        "production_write_authorized": False,
    }
    payload["request_sha256"] = _canonical_sha256(payload)
    return validate_dispatch_request(payload)


def validate_dispatch_request(payload: Mapping[str, Any]) -> dict[str, Any]:
    if not isinstance(payload, Mapping):
        raise CiscoAcceptanceDispatchRequestError("dispatch request must be an object")
    if set(payload) != _REQUIRED_KEYS:
        raise CiscoAcceptanceDispatchRequestError("dispatch request fields must match the closed schema")
    if payload.get("schema_version") != _SCHEMA:
        raise CiscoAcceptanceDispatchRequestError("unsupported dispatch request schema")

    request_id = str(payload.get("request_id", "")).strip()
    requested_by = str(payload.get("requested_by_ref", "")).strip()
    if not _REF.fullmatch(request_id) or not _REF.fullmatch(requested_by):
        raise CiscoAcceptanceDispatchRequestError("invalid dispatch request identity")

    stage = str(payload.get("stage", "")).strip().lower()
    workflow_file = _ALLOWED_STAGES.get(stage)
    if workflow_file is None:
        raise CiscoAcceptanceDispatchRequestError("stage is not in the read-only dispatch allowlist")

    target_ref = str(payload.get("target_ref", "")).strip()
    if not _TARGET_REF.fullmatch(target_ref):
        raise CiscoAcceptanceDispatchRequestError("target_ref is outside the Cisco domain branch boundary")

    source_sha = str(payload.get("expected_source_sha", "")).strip().lower()
    if not _SHA40.fullmatch(source_sha):
        raise CiscoAcceptanceDispatchRequestError("expected_source_sha must be an exact 40-character Git SHA")

    attestation = _sha256(payload.get("requested_by_attestation_sha256"), "requested_by_attestation_sha256")
    if payload.get("read_only_required") is not True:
        raise CiscoAcceptanceDispatchRequestError("dispatch request must require read-only execution")
    if payload.get("production_write_authorized") is not False:
        raise CiscoAcceptanceDispatchRequestError("dispatch request cannot authorize production writes")

    supplied = _sha256(payload.get("request_sha256"), "request_sha256")
    unsigned = dict(payload)
    unsigned.pop("request_sha256", None)
    expected = _canonical_sha256(unsigned)
    if not hmac.compare_digest(supplied, expected):
        raise CiscoAcceptanceDispatchRequestError("dispatch request digest mismatch")

    return {
        **unsigned,
        "requested_by_attestation_sha256": attestation,
        "workflow_file": workflow_file,
        "request_sha256": supplied,
        "physical_device_verified": False,
        "production_write_authorized": False,
    }
