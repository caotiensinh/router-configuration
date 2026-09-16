"""Static fail-closed audit for the Cisco acceptance dispatch surface."""

from __future__ import annotations

import hashlib
import json
from typing import Any


class CiscoAcceptanceDispatchBoundaryError(ValueError):
    pass


def _canonical_sha256(value: object) -> str:
    raw = json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()


def audit_dispatch_boundary(*, dispatcher_text: str, c03_text: str, c04_text: str) -> dict[str, Any]:
    required_dispatcher = (
        '"acceptance-dispatch/**"',
        '"acceptance/requests/*.json"',
        "contents: read",
        "actions: write",
        "validate_dispatch_request",
        "expected_source_sha",
        "dispatch_request_sha256",
    )
    missing = [token for token in required_dispatcher if token not in dispatcher_text]
    if missing:
        raise CiscoAcceptanceDispatchBoundaryError(f"dispatcher safety markers missing: {missing}")

    forbidden_dispatcher = (
        "contents: write",
        "cisco-recovery-observation.yml",
        "cisco-physical-evidence-ingest.yml",
        "c12_handover_manifest",
        "CISCO_NETCONF_PASSWORD",
        "CISCO_RESTCONF_PASSWORD",
        "edit_config(",
        "configure terminal",
        "write memory",
    )
    found = [token for token in forbidden_dispatcher if token in dispatcher_text]
    if found:
        raise CiscoAcceptanceDispatchBoundaryError(f"dispatcher crossed read-only boundary: {found}")

    for stage, text in (("c03", c03_text), ("c04", c04_text)):
        required = (
            "workflow_dispatch:",
            "expected_source_sha:",
            "required: true",
            "EXPECTED_SOURCE_SHA",
            "before network access",
            "if: github.event_name == 'workflow_dispatch'",
        )
        missing_stage = [token for token in required if token not in text]
        if missing_stage:
            raise CiscoAcceptanceDispatchBoundaryError(
                f"{stage} source-pin markers missing: {missing_stage}"
            )
        if "production_write_authorized" not in text:
            raise CiscoAcceptanceDispatchBoundaryError(f"{stage} lacks production-write boundary")

    if 'request_method_scope"] == ["GET"]' not in c04_text:
        raise CiscoAcceptanceDispatchBoundaryError("C04 workflow does not enforce GET-only evidence")
    for token in ("edit_config(", "configure terminal", "write memory"):
        if token in c03_text or token in c04_text:
            raise CiscoAcceptanceDispatchBoundaryError(f"live read-only workflow contains write token: {token}")

    result = {
        "schema_version": "cisco-acceptance-dispatch-boundary-audit/1",
        "dispatcher_request_branch_scoped": True,
        "dispatcher_actions_write_only_for_dispatch": True,
        "target_source_pins_verified": True,
        "c03_read_only_boundary_verified": True,
        "c04_get_only_boundary_verified": True,
        "production_write_authorized": False,
    }
    result["audit_sha256"] = _canonical_sha256(result)
    return result
