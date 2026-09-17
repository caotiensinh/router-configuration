"""Verifier for Cisco read-only acceptance dispatch receipts.

A dispatch receipt proves only that the GitHub workflow dispatch API accepted a
request against an exact source ref and returned a concrete workflow-run
identity. It is not live device evidence and cannot complete any Cisco
acceptance stage.
"""

from __future__ import annotations

import hashlib
import json
import re
from typing import Any, Mapping

_SHA40 = re.compile(r"^[0-9a-f]{40}$")
_SHA256 = re.compile(r"^[0-9a-f]{64}$")
_ALLOWED = {
    "c03": "cisco-netconf-live-readonly.yml",
    "c04": "cisco-restconf-live-readonly.yml",
}


class CiscoAcceptanceDispatchReceiptError(ValueError):
    pass


def _canonical_sha256(value: object) -> str:
    raw = json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()


def _sha256(value: object, label: str) -> str:
    text = str(value or "").strip().lower()
    if not _SHA256.fullmatch(text):
        raise CiscoAcceptanceDispatchReceiptError(f"{label} must be lowercase SHA-256")
    return text


def _workflow_run_identity(receipt: Mapping[str, Any]) -> tuple[int, str, str]:
    run_id = receipt.get("workflow_run_id")
    if not isinstance(run_id, int) or run_id <= 0:
        raise CiscoAcceptanceDispatchReceiptError("workflow_run_id must be a positive integer")
    run_url = str(receipt.get("run_url", "")).strip()
    html_url = str(receipt.get("html_url", "")).strip()
    expected_suffix = f"/actions/runs/{run_id}"
    if not run_url.endswith(expected_suffix) or not html_url.endswith(expected_suffix):
        raise CiscoAcceptanceDispatchReceiptError("workflow run URL identity mismatch")
    return run_id, run_url, html_url


def verify_dispatch_receipt(
    receipt: Mapping[str, Any],
    *,
    expected_request_sha256: str,
    expected_source_sha: str,
) -> dict[str, Any]:
    if receipt.get("schema_version") != "cisco-acceptance-dispatch-receipt/2":
        raise CiscoAcceptanceDispatchReceiptError("unexpected dispatch receipt schema")
    if receipt.get("production_write_authorized") is not False:
        raise CiscoAcceptanceDispatchReceiptError("dispatch receipt cannot authorize production writes")

    request_sha = _sha256(receipt.get("request_sha256"), "request_sha256")
    if request_sha != _sha256(expected_request_sha256, "expected_request_sha256"):
        raise CiscoAcceptanceDispatchReceiptError("dispatch receipt request digest mismatch")

    source_sha = str(receipt.get("expected_source_sha", "")).strip().lower()
    observed_sha = str(receipt.get("observed_source_sha", "")).strip().lower()
    expected = str(expected_source_sha).strip().lower()
    for value, label in (
        (source_sha, "expected_source_sha"),
        (observed_sha, "observed_source_sha"),
        (expected, "expected source"),
    ):
        if not _SHA40.fullmatch(value):
            raise CiscoAcceptanceDispatchReceiptError(f"{label} must be an exact Git SHA")
    if source_sha != expected or observed_sha != expected:
        raise CiscoAcceptanceDispatchReceiptError("dispatch receipt source continuity mismatch")

    stage = str(receipt.get("stage", "")).strip().lower()
    workflow = str(receipt.get("workflow_file", "")).strip()
    if _ALLOWED.get(stage) != workflow:
        raise CiscoAcceptanceDispatchReceiptError("dispatch receipt stage/workflow mismatch")
    if receipt.get("dispatch_status") != "dispatched" or receipt.get("http_status") != 200:
        raise CiscoAcceptanceDispatchReceiptError("dispatch receipt does not prove successful API dispatch")

    workflow_run_id, run_url, html_url = _workflow_run_identity(receipt)

    normalized = {
        "schema_version": "cisco-acceptance-dispatch-receipt-verification/2",
        "request_id": str(receipt.get("request_id", "")),
        "request_sha256": request_sha,
        "stage": stage,
        "target_ref": str(receipt.get("target_ref", "")),
        "source_sha": expected,
        "workflow_file": workflow,
        "workflow_run_id": workflow_run_id,
        "run_url": run_url,
        "html_url": html_url,
        "dispatch_api_accepted": True,
        "live_device_evidence_observed": False,
        "acceptance_stage_complete": False,
        "physical_device_verified": False,
        "production_write_authorized": False,
    }
    normalized["verification_sha256"] = _canonical_sha256(normalized)
    return normalized
