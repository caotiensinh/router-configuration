from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from typing import Any, Iterable, Mapping

from router_configuration.test_harness import (
    BackendKind,
    CommonScenario,
    EvidenceFidelity,
    ScenarioResult,
    TestBackendSpec,
    execute_vendor_test_plan,
    plan_vendor_tests,
)
from router_configuration.vendors.mikrotik.chr_scenario_bridge import (
    ValidatedChrScenarioEvidence,
    validate_chr_scenario_evidence,
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


def _base_version(value: Any) -> str:
    text = str(value or "").strip()
    if not text:
        raise ValueError("RouterOS version is required")
    return text.split()[0]


@dataclass(frozen=True)
class ChrFaultSuiteEntry:
    payload: Mapping[str, Any]
    evidence_ref: str


class _ChrFaultSuiteExecutor:
    vendor = "mikrotik"

    def __init__(
        self,
        *,
        backend_id: str,
        validated: Mapping[CommonScenario, ValidatedChrScenarioEvidence],
        evidence_refs: Mapping[CommonScenario, str],
    ) -> None:
        self.backend_id = backend_id
        self._validated = dict(validated)
        self._evidence_refs = dict(evidence_refs)

    def run_scenario(self, scenario: CommonScenario) -> ScenarioResult:
        if scenario not in self._validated:
            raise ValueError(f"no accepted CHR evidence is bound to {scenario.value}")
        return ScenarioResult.build(
            scenario=scenario,
            passed=True,
            evidence_ref=self._evidence_refs[scenario],
            fidelity=EvidenceFidelity.VENDOR_OS,
        )


def build_chr_fault_suite_test_bundle(
    entries: Iterable[ChrFaultSuiteEntry],
    *,
    backend_id: str = "mikrotik-chr-fault-suite",
) -> dict[str, Any]:
    """Aggregate independent accepted CHR fault runs under one common test plan.

    Each source remains independently hash-bound to its original workflow evidence.
    This function does not rerun RouterOS and does not upgrade evidence fidelity.
    """

    validated_by_scenario: dict[CommonScenario, ValidatedChrScenarioEvidence] = {}
    refs_by_scenario: dict[CommonScenario, str] = {}
    source_rows: list[dict[str, Any]] = []
    routeros_bases: set[str] = set()

    for entry in entries:
        validated = validate_chr_scenario_evidence(entry.payload)
        if validated.scenario in validated_by_scenario:
            raise ValueError(f"duplicate CHR suite evidence for {validated.scenario.value}")
        ref = str(entry.evidence_ref or "").strip()
        if not ref:
            raise ValueError(f"evidence_ref is required for {validated.scenario.value}")
        version = _base_version(validated.provenance.get("routeros_version"))
        routeros_bases.add(version)
        validated_by_scenario[validated.scenario] = validated
        refs_by_scenario[validated.scenario] = ref
        source_rows.append(
            {
                "scenario": validated.scenario.value,
                "source_schema_version": str(entry.payload["schema_version"]),
                "source_evidence_sha256": validated.source_evidence_sha256,
                "evidence_ref": ref,
                "provenance": dict(validated.provenance),
            }
        )

    if not validated_by_scenario:
        raise ValueError("at least one accepted CHR scenario evidence record is required")
    if len(routeros_bases) != 1:
        raise ValueError("CHR fault suite evidence must use one RouterOS base version")

    capabilities: set[str] = set()
    if CommonScenario.DNS_FAILURE in validated_by_scenario:
        capabilities.add("dns")
    if CommonScenario.WAN_FAILOVER in validated_by_scenario:
        capabilities.update(("multiwan", "routing"))
    if CommonScenario.DEFAULT_ROUTE_LOSS in validated_by_scenario:
        capabilities.add("routing")

    backend = TestBackendSpec.build(
        backend_id=backend_id,
        vendor="mikrotik",
        kind=BackendKind.VIRTUAL_APPLIANCE,
        fidelity=EvidenceFidelity.VENDOR_OS,
        capabilities=capabilities,
        hardware_present=False,
        lab_disposable=True,
        fault_injection_allowed=True,
        snapshot_restore_available=False,
        production_write_authorized=False,
    )
    plan = plan_vendor_tests(backend, validated_by_scenario.keys())
    executor = _ChrFaultSuiteExecutor(
        backend_id=backend.backend_id,
        validated=validated_by_scenario,
        evidence_refs=refs_by_scenario,
    )
    assessment = execute_vendor_test_plan(plan, executor).as_dict()

    bundle = {
        "schema_version": "mikrotik-chr-fault-suite-common-test/1",
        "routeros_base_version": next(iter(routeros_bases)),
        "scenario_count": len(validated_by_scenario),
        "source_evidence": sorted(source_rows, key=lambda row: row["scenario"]),
        "plan": plan.as_dict(),
        "assessment": assessment,
        "suite_scope_acceptance_passed": bool(assessment["software_acceptance_passed"]),
        "whole_vendor_software_certification_claimed": False,
        "hardware_certification_claimed": False,
        "production_writer_available": False,
        "write_authorized": False,
    }
    bundle["bundle_sha256"] = _canonical_sha256(bundle)
    return bundle
