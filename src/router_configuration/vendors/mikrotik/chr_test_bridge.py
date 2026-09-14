from __future__ import annotations

import hashlib
import json
from typing import Any, Mapping

from router_configuration.test_harness import (
    BackendKind,
    CommonScenario,
    EvidenceFidelity,
    ScenarioResult,
    TestBackendSpec,
    execute_vendor_test_plan,
    plan_vendor_tests,
)

_EXPECTED_SCHEMA = "mikrotik-script-compiler-chr-acceptance/1"
_HEX64_FIELDS = (
    "script_sha256",
    "semantic_attestation_sha256",
    "dry_run_evidence_sha256",
    "knowledge_sha256",
    "approval_sha256",
)


def _canonical_sha256(value: Any) -> str:
    encoded = json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        default=str,
    ).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def _require_hex64(payload: Mapping[str, Any], field: str) -> None:
    value = str(payload.get(field) or "").strip().lower()
    if len(value) != 64 or any(ch not in "0123456789abcdef" for ch in value):
        raise ValueError(f"{field} must be a 64-character SHA-256 digest")


def validate_chr_script_compiler_acceptance(payload: Mapping[str, Any]) -> None:
    """Validate accepted live-CHR compiler evidence before common-harness reuse."""

    if payload.get("schema_version") != _EXPECTED_SCHEMA:
        raise ValueError("unexpected CHR script-compiler acceptance schema")
    if payload.get("ok") is not True:
        raise ValueError("CHR script-compiler acceptance is not PASS")
    if payload.get("negative_control_rejected") is not True:
        raise ValueError("CHR negative control was not rejected")
    if payload.get("configuration_unchanged") is not True:
        raise ValueError("CHR dry-run changed configuration")
    if payload.get("temporary_files_removed") is not True:
        raise ValueError("CHR temporary files were not removed")
    if payload.get("write_authorized") is not False:
        raise ValueError("CHR acceptance must keep write_authorized=false")
    if not str(payload.get("routeros_observed_version") or "").strip():
        raise ValueError("CHR acceptance is missing observed RouterOS version")
    for field in _HEX64_FIELDS:
        _require_hex64(payload, field)


class ChrScriptCompilerEvidenceExecutor:
    """Adapt accepted live-CHR evidence to one vendor-neutral test scenario.

    This class does not connect to RouterOS. The live RouterOS work has already
    happened in the CHR workflow and is represented by the validated acceptance
    evidence supplied to this bridge.
    """

    vendor = "mikrotik"

    def __init__(
        self,
        *,
        backend_id: str,
        acceptance: Mapping[str, Any],
        evidence_ref: str,
    ) -> None:
        self.backend_id = str(backend_id)
        self._acceptance = dict(acceptance)
        self._evidence_ref = str(evidence_ref)
        validate_chr_script_compiler_acceptance(self._acceptance)
        if not self._evidence_ref.strip():
            raise ValueError("evidence_ref is required")

    def run_scenario(self, scenario: CommonScenario) -> ScenarioResult:
        if scenario is not CommonScenario.RENDER_VALIDATE:
            raise ValueError(
                "CHR script-compiler evidence can only satisfy render_validate"
            )
        return ScenarioResult.build(
            scenario=scenario,
            passed=True,
            evidence_ref=self._evidence_ref,
            fidelity=EvidenceFidelity.VENDOR_OS,
        )


def build_chr_script_compiler_test_bundle(
    acceptance: Mapping[str, Any],
    *,
    evidence_ref: str,
    backend_id: str = "mikrotik-chr-script-compiler",
) -> dict[str, Any]:
    """Build a common-harness assessment from existing live CHR evidence."""

    validate_chr_script_compiler_acceptance(acceptance)
    backend = TestBackendSpec.build(
        backend_id=backend_id,
        vendor="mikrotik",
        kind=BackendKind.VIRTUAL_APPLIANCE,
        fidelity=EvidenceFidelity.VENDOR_OS,
        capabilities=("render_validate",),
        hardware_present=False,
        lab_disposable=True,
        fault_injection_allowed=False,
        snapshot_restore_available=False,
        production_write_authorized=False,
    )
    plan = plan_vendor_tests(backend, (CommonScenario.RENDER_VALIDATE,))
    executor = ChrScriptCompilerEvidenceExecutor(
        backend_id=backend.backend_id,
        acceptance=acceptance,
        evidence_ref=evidence_ref,
    )
    assessment = execute_vendor_test_plan(plan, executor).as_dict()
    payload = {
        "schema_version": "mikrotik-chr-common-test-bridge/1",
        "source_schema_version": _EXPECTED_SCHEMA,
        "routeros_observed_version": str(acceptance["routeros_observed_version"]),
        "plan": plan.as_dict(),
        "assessment": assessment,
        "hardware_certification_claimed": False,
        "production_writer_available": False,
        "write_authorized": False,
    }
    payload["bundle_sha256"] = _canonical_sha256(payload)
    return payload
