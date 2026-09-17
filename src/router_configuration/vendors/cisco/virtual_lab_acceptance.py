"""Fail-closed IOS XE virtual-lab acceptance bridge for Cisco C09.

The repository does not ship, download, or license Cisco images. This module
validates evidence produced by an identified, disposable IOS XE virtual appliance
and projects that evidence into the repository's common network-device harness.
It contains no transport and no production writer.
"""

from __future__ import annotations

import hashlib
import json
import re
from typing import Any, Mapping

from router_configuration.test_harness import (
    BackendKind,
    CommonScenario,
    EvidenceFidelity,
    ScenarioResult,
    TestBackendSpec,
    evaluate_vendor_test_results,
    plan_vendor_tests,
)
from router_configuration.test_lab import StandardLabTopology

from .platforms import CiscoDeviceRole, assess_read_only_candidate
from .validation_approval import CiscoApprovalBinding

_EXPECTED_SCHEMA = "cisco-iosxe-virtual-lab-evidence/1"
_EXPECTED_ORIGIN = "live_iosxe_virtual_appliance"
_REQUIRED_SCENARIOS = (
    CommonScenario.READ_ONLY_DISCOVERY,
    CommonScenario.RENDER_VALIDATE,
    CommonScenario.CONFIGURATION_ROUNDTRIP,
    CommonScenario.MANAGEMENT_SURVIVAL,
)
_REQUIRED_CAPABILITIES = (
    "discovery",
    "render_validate",
    "config_roundtrip",
    "management_probe",
)
_HEX40 = re.compile(r"^[0-9a-f]{40}$")
_HEX64 = re.compile(r"^[0-9a-f]{64}$")
_OPAQUE_REF = re.compile(r"^[A-Za-z0-9_.:/-]{1,160}$")


class CiscoVirtualLabEvidenceError(ValueError):
    """Raised when C09 evidence does not meet the virtual-lab contract."""


def _canonical_sha256(value: object) -> str:
    raw = json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        default=str,
    ).encode("utf-8")
    return hashlib.sha256(raw).hexdigest()


def _require_sha256(value: object, label: str) -> str:
    text = str(value or "").strip().lower()
    if not _HEX64.fullmatch(text):
        raise CiscoVirtualLabEvidenceError(f"{label} must be a lowercase SHA-256 digest")
    return text


def _require_sha40(value: object, label: str) -> str:
    text = str(value or "").strip().lower()
    if not _HEX40.fullmatch(text):
        raise CiscoVirtualLabEvidenceError(f"{label} must be a 40-character lowercase Git SHA")
    return text


def _require_opaque(value: object, label: str) -> str:
    text = str(value or "").strip()
    if not _OPAQUE_REF.fullmatch(text):
        raise CiscoVirtualLabEvidenceError(f"{label} must be an opaque non-secret reference")
    lowered = text.lower()
    if any(marker in lowered for marker in ("http://", "https://", "password", "token", "secret", "private_key")):
        raise CiscoVirtualLabEvidenceError(f"{label} must not contain endpoint or secret material")
    return text


def _require_false(payload: Mapping[str, Any], field: str) -> None:
    if payload.get(field) is not False:
        raise CiscoVirtualLabEvidenceError(f"{field} must remain false")


def _require_true(payload: Mapping[str, Any], field: str) -> None:
    if payload.get(field) is not True:
        raise CiscoVirtualLabEvidenceError(f"{field} must be true")


def validate_cisco_virtual_lab_evidence(
    payload: Mapping[str, Any],
    *,
    approval: CiscoApprovalBinding,
) -> None:
    """Validate live C8000V evidence and bind it to the exact C08 fingerprint."""

    if payload.get("schema_version") != _EXPECTED_SCHEMA:
        raise CiscoVirtualLabEvidenceError("unexpected Cisco virtual-lab evidence schema")
    if payload.get("evidence_origin") != _EXPECTED_ORIGIN:
        raise CiscoVirtualLabEvidenceError("C09 requires live IOS XE virtual-appliance evidence")
    if payload.get("vendor") != "Cisco" or payload.get("os_family") != "IOS XE":
        raise CiscoVirtualLabEvidenceError("virtual-lab vendor/OS identity mismatch")
    if payload.get("backend_kind") != BackendKind.VIRTUAL_APPLIANCE.value:
        raise CiscoVirtualLabEvidenceError("C09 requires a virtual_appliance backend")

    backend_id = _require_opaque(payload.get("backend_id"), "backend_id")
    target_id = _require_opaque(payload.get("target_id"), "target_id")
    if target_id != approval.target_id:
        raise CiscoVirtualLabEvidenceError("virtual-lab target differs from the C08 approval target")

    model = str(payload.get("model") or "").strip()
    version = str(payload.get("iosxe_version") or "").strip()
    decision = assess_read_only_candidate(model, version)
    if not decision.read_only_candidate:
        raise CiscoVirtualLabEvidenceError(f"virtual-lab platform/version not admitted: {decision.status}")
    if decision.family != "Catalyst 8000V" or decision.role is not CiscoDeviceRole.ROUTER:
        raise CiscoVirtualLabEvidenceError("initial C09 adapter is bounded to Catalyst 8000V router evidence")
    if model != approval.model or version != approval.iosxe_version:
        raise CiscoVirtualLabEvidenceError("virtual-lab model/version differs from the C08 approval binding")
    if decision.documentation_train != approval.documentation_train:
        raise CiscoVirtualLabEvidenceError("virtual-lab documentation train differs from C08")

    _require_sha40(payload.get("source_sha"), "source_sha")
    run_id = str(payload.get("source_run_id") or "").strip()
    if not run_id.isdigit() or int(run_id) <= 0:
        raise CiscoVirtualLabEvidenceError("source_run_id must identify a positive workflow/lab run")
    _require_sha256(payload.get("artifact_digest_sha256"), "artifact_digest_sha256")
    _require_sha256(payload.get("observed_identity_sha256"), "observed_identity_sha256")

    schema_digest = _require_sha256(
        payload.get("schema_inventory_digest_sha256"),
        "schema_inventory_digest_sha256",
    )
    if schema_digest != approval.schema_inventory_digest_sha256:
        raise CiscoVirtualLabEvidenceError("virtual-lab schema inventory differs from C08")
    if _require_sha256(payload.get("pre_state_sha256"), "pre_state_sha256") != approval.pre_state_sha256:
        raise CiscoVirtualLabEvidenceError("virtual-lab pre-state differs from C08")
    if _require_sha256(payload.get("payload_digest_sha256"), "payload_digest_sha256") != approval.payload_digest_sha256:
        raise CiscoVirtualLabEvidenceError("virtual-lab payload differs from C08")
    if _require_sha256(payload.get("approval_sha256"), "approval_sha256") != approval.approval_sha256:
        raise CiscoVirtualLabEvidenceError("virtual-lab approval fingerprint differs from C08")
    _require_sha256(payload.get("post_state_sha256"), "post_state_sha256")

    topology_sha = StandardLabTopology.build().as_dict()["topology_sha256"]
    if _require_sha256(payload.get("topology_sha256"), "topology_sha256") != topology_sha:
        raise CiscoVirtualLabEvidenceError("virtual-lab topology differs from the common topology contract")

    for field in (
        "identity_observed",
        "lab_disposable",
        "fault_injection_lab_only",
        "lab_change_approved",
        "intended_state_verified",
        "management_survived_fault",
        "target_discarded_or_sanitized_after_run",
    ):
        _require_true(payload, field)
    for field in (
        "image_embedded_in_repository",
        "license_material_present",
        "hardware_present",
        "physical_hardware_claimed",
        "production_writer_available",
        "production_write_authorized",
    ):
        _require_false(payload, field)

    raw_scenarios = payload.get("scenarios")
    if not isinstance(raw_scenarios, list):
        raise CiscoVirtualLabEvidenceError("scenarios must be a list")
    seen: set[CommonScenario] = set()
    for item in raw_scenarios:
        if not isinstance(item, Mapping):
            raise CiscoVirtualLabEvidenceError("scenario evidence must be objects")
        try:
            scenario = CommonScenario(str(item.get("scenario")))
        except ValueError as exc:
            raise CiscoVirtualLabEvidenceError("unknown scenario in C09 evidence") from exc
        if scenario in seen:
            raise CiscoVirtualLabEvidenceError(f"duplicate scenario evidence: {scenario.value}")
        seen.add(scenario)
        if scenario not in _REQUIRED_SCENARIOS:
            raise CiscoVirtualLabEvidenceError(f"unexpected C09 scenario: {scenario.value}")
        if item.get("passed") is not True:
            raise CiscoVirtualLabEvidenceError(f"C09 scenario did not pass: {scenario.value}")
        if item.get("fidelity") != EvidenceFidelity.VENDOR_OS.label:
            raise CiscoVirtualLabEvidenceError(f"C09 scenario lacks vendor_os fidelity: {scenario.value}")
        _require_opaque(item.get("evidence_ref"), f"{scenario.value}.evidence_ref")

    if seen != set(_REQUIRED_SCENARIOS):
        missing = sorted(item.value for item in set(_REQUIRED_SCENARIOS) - seen)
        raise CiscoVirtualLabEvidenceError("missing required C09 scenarios: " + ", ".join(missing))

    # Keep the local variable used so static checks can prove backend identity was validated.
    if not backend_id:
        raise CiscoVirtualLabEvidenceError("backend_id is required")


def build_cisco_virtual_lab_bundle(
    payload: Mapping[str, Any],
    *,
    approval: CiscoApprovalBinding,
) -> dict[str, Any]:
    """Project validated live IOS XE evidence into the common test harness."""

    validate_cisco_virtual_lab_evidence(payload, approval=approval)
    backend = TestBackendSpec.build(
        backend_id=str(payload["backend_id"]),
        vendor="cisco",
        kind=BackendKind.VIRTUAL_APPLIANCE,
        fidelity=EvidenceFidelity.VENDOR_OS,
        capabilities=_REQUIRED_CAPABILITIES,
        hardware_present=False,
        lab_disposable=True,
        fault_injection_allowed=True,
        snapshot_restore_available=False,
        production_write_authorized=False,
    )
    plan = plan_vendor_tests(backend, _REQUIRED_SCENARIOS)
    if set(plan.runnable()) != set(_REQUIRED_SCENARIOS) or plan.deferred():
        raise CiscoVirtualLabEvidenceError("common harness did not admit every required C09 scenario")

    results = tuple(
        ScenarioResult.build(
            scenario=str(item["scenario"]),
            passed=True,
            evidence_ref=str(item["evidence_ref"]),
            fidelity=EvidenceFidelity.VENDOR_OS,
        )
        for item in payload["scenarios"]
    )
    assessment = evaluate_vendor_test_results(plan, results).as_dict()
    source_evidence_sha256 = _canonical_sha256(payload)
    bundle = {
        "schema_version": "cisco-iosxe-virtual-lab-common-bridge/1",
        "source_schema_version": _EXPECTED_SCHEMA,
        "source_evidence_sha256": source_evidence_sha256,
        "source_sha": str(payload["source_sha"]),
        "source_run_id": str(payload["source_run_id"]),
        "artifact_digest_sha256": str(payload["artifact_digest_sha256"]),
        "model": str(payload["model"]),
        "iosxe_version": str(payload["iosxe_version"]),
        "target_id": str(payload["target_id"]),
        "approval_sha256": approval.approval_sha256,
        "plan": plan.as_dict(),
        "assessment": assessment,
        "live_virtual_iosxe_observed": True,
        "c09_complete": True,
        "physical_hardware_claimed": False,
        "production_writer_available": False,
        "production_write_authorized": False,
    }
    bundle["bundle_sha256"] = _canonical_sha256(bundle)
    return bundle


def contract_only_status() -> dict[str, Any]:
    """Return CI-safe status; synthetic contract tests can never close C09."""

    payload = {
        "schema_version": "cisco-c09-contract-status/1",
        "required_backend": "Catalyst 8000V IOS XE virtual appliance",
        "required_scenarios": [item.value for item in _REQUIRED_SCENARIOS],
        "synthetic_fixture_can_complete_c09": False,
        "live_virtual_iosxe_observed": False,
        "c09_complete": False,
        "physical_hardware_claimed": False,
        "production_writer_available": False,
        "production_write_authorized": False,
    }
    payload["status_sha256"] = _canonical_sha256(payload)
    return payload
