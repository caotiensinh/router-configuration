"""Correlation record between a read-only dispatch request and live evidence.

The correlation is deliberately non-promoting: it proves source/request/evidence
continuity but does not itself accept the evidence into the repository ledger.
"""

from __future__ import annotations

import hashlib
import json
import re
from typing import Any, Mapping

_SHA40 = re.compile(r"^[0-9a-f]{40}$")
_SHA256 = re.compile(r"^[0-9a-f]{64}$")
_STAGE_SCHEMAS = {
    "c03": "cisco-c03-live-evidence/1",
    "c04": "cisco-c04-live-restconf-evidence/2",
}


class CiscoAcceptanceDispatchCorrelationError(ValueError):
    pass


def _canonical_sha256(value: object) -> str:
    raw = json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()


def _sha256(value: object, label: str) -> str:
    text = str(value or "").strip().lower()
    if not _SHA256.fullmatch(text):
        raise CiscoAcceptanceDispatchCorrelationError(f"{label} must be lowercase SHA-256")
    return text


def correlate_live_evidence(
    live_evidence: Mapping[str, Any],
    *,
    stage: str,
    dispatch_request_id: str,
    dispatch_request_sha256: str,
    expected_source_sha: str,
) -> dict[str, Any]:
    normalized_stage = str(stage).strip().lower()
    expected_schema = _STAGE_SCHEMAS.get(normalized_stage)
    if expected_schema is None:
        raise CiscoAcceptanceDispatchCorrelationError("unsupported read-only acceptance stage")
    if live_evidence.get("schema_version") != expected_schema:
        raise CiscoAcceptanceDispatchCorrelationError("live evidence schema/stage mismatch")

    source = str(expected_source_sha).strip().lower()
    observed_source = str(live_evidence.get("source_sha", "")).strip().lower()
    if not _SHA40.fullmatch(source) or observed_source != source:
        raise CiscoAcceptanceDispatchCorrelationError("live evidence source continuity mismatch")
    request_sha = _sha256(dispatch_request_sha256, "dispatch_request_sha256")
    request_id = str(dispatch_request_id).strip()
    if not request_id or len(request_id) > 160:
        raise CiscoAcceptanceDispatchCorrelationError("invalid dispatch request id")

    if live_evidence.get("production_write_authorized") is not False:
        raise CiscoAcceptanceDispatchCorrelationError("live evidence crossed production-write boundary")
    if live_evidence.get("write_operations_performed") is not False:
        raise CiscoAcceptanceDispatchCorrelationError("live evidence reports a write operation")

    if normalized_stage == "c03":
        if live_evidence.get("c03_complete") is not True or live_evidence.get("hostkey_verified") is not True:
            raise CiscoAcceptanceDispatchCorrelationError("C03 live evidence is not complete")
    else:
        if live_evidence.get("c04_complete") is not True or live_evidence.get("result") != "live_readonly_admitted":
            raise CiscoAcceptanceDispatchCorrelationError("C04 live evidence is not complete")
        if live_evidence.get("request_method_scope") != ["GET"]:
            raise CiscoAcceptanceDispatchCorrelationError("C04 evidence is not GET-only")

    result = {
        "schema_version": "cisco-acceptance-dispatch-correlation/1",
        "stage": normalized_stage,
        "dispatch_request_id": request_id,
        "dispatch_request_sha256": request_sha,
        "source_sha": source,
        "live_evidence_sha256": _canonical_sha256(dict(live_evidence)),
        "source_continuity_verified": True,
        "read_only_live_evidence_verified": True,
        "repository_evidence_accepted": False,
        "acceptance_stage_complete": False,
        "physical_device_verified": False,
        "production_write_authorized": False,
    }
    result["correlation_sha256"] = _canonical_sha256(result)
    return result
