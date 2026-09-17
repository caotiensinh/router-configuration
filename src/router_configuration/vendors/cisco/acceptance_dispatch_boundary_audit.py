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


def _require_tokens(text: str, tokens: tuple[str, ...], label: str) -> None:
    missing = [token for token in tokens if token not in text]
    if missing:
        raise CiscoAcceptanceDispatchBoundaryError(f"{label} safety markers missing: {missing}")


def audit_dispatch_boundary(*, dispatcher_text: str, c03_text: str, c04_text: str) -> dict[str, Any]:
    required_dispatcher = (
        '"acceptance-dispatch/**"',
        '"acceptance/requests/*.json"',
        "contents: read",
        "actions: write",
        "validate_dispatch_request",
        "expected_source_sha",
        "dispatch_request_sha256",
        "Verify target ref remains at exact requested source SHA",
        "uses: ./.github/workflows/cisco-netconf-live-readonly.yml",
        "if: needs.validate.outputs.stage == 'c03'",
        "if: needs.validate.outputs.stage == 'c04'",
        "live_execution_requested: true",
        "CISCO_NETCONF_PASSWORD: ${{ secrets.CISCO_NETCONF_PASSWORD }}",
    )
    _require_tokens(dispatcher_text, required_dispatcher, "dispatcher")

    forbidden_dispatcher = (
        "contents: write",
        "cisco-recovery-observation.yml",
        "cisco-physical-evidence-ingest.yml",
        "c12_handover_manifest",
        "secrets: inherit",
        "edit_config(",
        "configure terminal",
        "write memory",
    )
    found = [token for token in forbidden_dispatcher if token in dispatcher_text]
    if found:
        raise CiscoAcceptanceDispatchBoundaryError(f"dispatcher crossed read-only boundary: {found}")

    common_stage_markers = (
        "workflow_dispatch:",
        "expected_source_sha:",
        "required: true",
        "EXPECTED_SOURCE_SHA",
        "before network access",
        "production_write_authorized",
    )
    _require_tokens(c03_text, common_stage_markers, "c03 source-pin")
    _require_tokens(c04_text, common_stage_markers, "c04 source-pin")

    c03_reusable_markers = (
        "workflow_call:",
        "live_execution_requested:",
        "inputs.live_execution_requested == true",
        "runs-on: self-hosted",
        "aiserver-router-configuration",
        "git rev-parse HEAD",
        "ref: ${{ inputs.expected_source_sha }}",
    )
    _require_tokens(c03_text, c03_reusable_markers, "c03 reusable owner-gated")

    c04_dispatch_markers = (
        "if: github.event_name == 'workflow_dispatch'",
        'request_method_scope"] == ["GET"]',
    )
    _require_tokens(c04_text, c04_dispatch_markers, "c04 dispatch")

    for token in ("edit_config(", "configure terminal", "write memory"):
        if token in c03_text or token in c04_text:
            raise CiscoAcceptanceDispatchBoundaryError(f"live read-only workflow contains write token: {token}")

    result = {
        "schema_version": "cisco-acceptance-dispatch-boundary-audit/1",
        "dispatcher_request_branch_scoped": True,
        "dispatcher_actions_write_only_for_c04_dispatch": True,
        "c03_owner_preserving_reusable_call_verified": True,
        "target_source_pins_verified": True,
        "c03_reusable_owner_gate_path_verified": True,
        "c03_read_only_boundary_verified": True,
        "c04_get_only_boundary_verified": True,
        "production_write_authorized": False,
    }
    result["audit_sha256"] = _canonical_sha256(result)
    return result
