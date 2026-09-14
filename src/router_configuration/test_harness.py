from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from enum import Enum, IntEnum
from typing import Any, Iterable, Mapping, Protocol


class BackendKind(str, Enum):
    BEHAVIOR_MODEL = "behavior_model"
    SIMULATOR = "simulator"
    SOFTWARE_CONTROLLER = "software_controller"
    VIRTUAL_APPLIANCE = "virtual_appliance"
    PHYSICAL_DEVICE = "physical_device"


class EvidenceFidelity(IntEnum):
    CONTRACT = 0
    BEHAVIOR = 1
    VENDOR_OS = 2
    PHYSICAL = 3

    @property
    def label(self) -> str:
        return {
            EvidenceFidelity.CONTRACT: "contract",
            EvidenceFidelity.BEHAVIOR: "behavior",
            EvidenceFidelity.VENDOR_OS: "vendor_os",
            EvidenceFidelity.PHYSICAL: "physical",
        }[self]


class ScenarioDisposition(str, Enum):
    RUN = "run"
    DEFERRED = "deferred"


class CommonScenario(str, Enum):
    READ_ONLY_DISCOVERY = "read_only_discovery"
    RENDER_VALIDATE = "render_validate"
    CONFIGURATION_ROUNDTRIP = "configuration_roundtrip"
    BACKUP_RESTORE = "backup_restore"
    MANAGEMENT_SURVIVAL = "management_survival"
    WAN_FAILOVER = "wan_failover"
    DNS_FAILURE = "dns_failure"
    DEFAULT_ROUTE_LOSS = "default_route_loss"
    VPN_RECOVERY = "vpn_recovery"
    ROLLBACK_RECOVERY = "rollback_recovery"
    HARDWARE_DATAPLANE = "hardware_dataplane"
    PERFORMANCE_CAPACITY = "performance_capacity"


@dataclass(frozen=True)
class ScenarioRequirement:
    scenario: CommonScenario
    min_fidelity: EvidenceFidelity
    required_capabilities: tuple[str, ...] = ()
    requires_disposable_target: bool = False
    requires_fault_injection: bool = False
    requires_snapshot_restore: bool = False
    requires_hardware: bool = False


SCENARIO_REQUIREMENTS: tuple[ScenarioRequirement, ...] = (
    ScenarioRequirement(
        CommonScenario.READ_ONLY_DISCOVERY,
        EvidenceFidelity.BEHAVIOR,
        ("discovery",),
    ),
    ScenarioRequirement(
        CommonScenario.RENDER_VALIDATE,
        EvidenceFidelity.CONTRACT,
        ("render_validate",),
    ),
    ScenarioRequirement(
        CommonScenario.CONFIGURATION_ROUNDTRIP,
        EvidenceFidelity.VENDOR_OS,
        ("config_roundtrip",),
        requires_disposable_target=True,
    ),
    ScenarioRequirement(
        CommonScenario.BACKUP_RESTORE,
        EvidenceFidelity.VENDOR_OS,
        ("config_backup", "config_restore"),
        requires_disposable_target=True,
    ),
    ScenarioRequirement(
        CommonScenario.MANAGEMENT_SURVIVAL,
        EvidenceFidelity.VENDOR_OS,
        ("management_probe",),
        requires_disposable_target=True,
        requires_fault_injection=True,
    ),
    ScenarioRequirement(
        CommonScenario.WAN_FAILOVER,
        EvidenceFidelity.VENDOR_OS,
        ("multiwan", "routing"),
        requires_disposable_target=True,
        requires_fault_injection=True,
    ),
    ScenarioRequirement(
        CommonScenario.DNS_FAILURE,
        EvidenceFidelity.VENDOR_OS,
        ("dns",),
        requires_disposable_target=True,
        requires_fault_injection=True,
    ),
    ScenarioRequirement(
        CommonScenario.DEFAULT_ROUTE_LOSS,
        EvidenceFidelity.VENDOR_OS,
        ("routing",),
        requires_disposable_target=True,
        requires_fault_injection=True,
    ),
    ScenarioRequirement(
        CommonScenario.VPN_RECOVERY,
        EvidenceFidelity.VENDOR_OS,
        ("vpn", "routing"),
        requires_disposable_target=True,
        requires_fault_injection=True,
    ),
    ScenarioRequirement(
        CommonScenario.ROLLBACK_RECOVERY,
        EvidenceFidelity.VENDOR_OS,
        ("config_roundtrip",),
        requires_disposable_target=True,
        requires_fault_injection=True,
        requires_snapshot_restore=True,
    ),
    ScenarioRequirement(
        CommonScenario.HARDWARE_DATAPLANE,
        EvidenceFidelity.PHYSICAL,
        ("hardware_dataplane",),
        requires_hardware=True,
    ),
    ScenarioRequirement(
        CommonScenario.PERFORMANCE_CAPACITY,
        EvidenceFidelity.PHYSICAL,
        ("performance",),
        requires_hardware=True,
    ),
)


_REQUIREMENT_BY_SCENARIO = {item.scenario: item for item in SCENARIO_REQUIREMENTS}

_VENDOR_ALIASES = {
    "routeros": "mikrotik",
    "microtik": "mikrotik",
    "ios": "cisco",
    "ios-xe": "cisco",
    "iosxe": "cisco",
    "tplink": "tp-link",
    "tp_link": "tp-link",
    "omada": "tp-link",
    "fortigate": "fortinet",
    "forti-gate": "fortinet",
}

_FORBIDDEN_REF_MARKERS = (
    "http://",
    "https://",
    "password",
    "passwd",
    "token=",
    "secret=",
    "private_key",
)


def canonical_vendor(value: str) -> str:
    normalized = str(value or "").strip().lower().replace(" ", "-")
    if not normalized:
        raise ValueError("vendor is required")
    return _VENDOR_ALIASES.get(normalized, normalized)


def _canonical_sha256(value: Any) -> str:
    encoded = json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        default=str,
    ).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def _normalize_capabilities(values: Iterable[str]) -> frozenset[str]:
    result = {
        str(item).strip().lower().replace("-", "_")
        for item in values
        if str(item).strip()
    }
    return frozenset(result)


@dataclass(frozen=True)
class TestBackendSpec:
    backend_id: str
    vendor: str
    kind: BackendKind
    fidelity: EvidenceFidelity
    capabilities: frozenset[str]
    hardware_present: bool = False
    lab_disposable: bool = True
    fault_injection_allowed: bool = False
    snapshot_restore_available: bool = False
    production_write_authorized: bool = False

    @classmethod
    def build(
        cls,
        *,
        backend_id: str,
        vendor: str,
        kind: BackendKind | str,
        fidelity: EvidenceFidelity | int,
        capabilities: Iterable[str],
        hardware_present: bool = False,
        lab_disposable: bool = True,
        fault_injection_allowed: bool = False,
        snapshot_restore_available: bool = False,
        production_write_authorized: bool = False,
    ) -> "TestBackendSpec":
        obj = cls(
            backend_id=str(backend_id or "").strip(),
            vendor=canonical_vendor(vendor),
            kind=kind if isinstance(kind, BackendKind) else BackendKind(str(kind)),
            fidelity=fidelity if isinstance(fidelity, EvidenceFidelity) else EvidenceFidelity(int(fidelity)),
            capabilities=_normalize_capabilities(capabilities),
            hardware_present=bool(hardware_present),
            lab_disposable=bool(lab_disposable),
            fault_injection_allowed=bool(fault_injection_allowed),
            snapshot_restore_available=bool(snapshot_restore_available),
            production_write_authorized=bool(production_write_authorized),
        )
        obj.validate()
        return obj

    def validate(self) -> None:
        if not self.backend_id:
            raise ValueError("backend_id is required")
        lowered = self.backend_id.lower()
        if any(marker in lowered for marker in _FORBIDDEN_REF_MARKERS):
            raise ValueError("backend_id must be an opaque non-secret identifier")
        if self.production_write_authorized:
            raise ValueError("test harness cannot authorize production writes")
        if self.kind is BackendKind.PHYSICAL_DEVICE:
            if not self.hardware_present:
                raise ValueError("physical_device backend requires hardware_present=true")
            if self.fidelity is not EvidenceFidelity.PHYSICAL:
                raise ValueError("physical_device backend requires physical fidelity")
        else:
            if self.hardware_present:
                raise ValueError("non-physical backend cannot claim hardware_present=true")
            if self.fidelity is EvidenceFidelity.PHYSICAL:
                raise ValueError("non-physical backend cannot claim physical fidelity")
        if self.kind is BackendKind.VIRTUAL_APPLIANCE and self.fidelity < EvidenceFidelity.VENDOR_OS:
            raise ValueError("virtual_appliance must provide at least vendor_os fidelity")
        if self.kind is BackendKind.BEHAVIOR_MODEL and self.fidelity > EvidenceFidelity.BEHAVIOR:
            raise ValueError("behavior_model cannot claim vendor_os or physical fidelity")

    def as_dict(self) -> dict[str, Any]:
        return {
            "backend_id": self.backend_id,
            "vendor": self.vendor,
            "kind": self.kind.value,
            "fidelity": self.fidelity.label,
            "capabilities": sorted(self.capabilities),
            "hardware_present": self.hardware_present,
            "lab_disposable": self.lab_disposable,
            "fault_injection_allowed": self.fault_injection_allowed,
            "snapshot_restore_available": self.snapshot_restore_available,
            "production_writer_available": False,
            "write_authorized": False,
        }


@dataclass(frozen=True)
class PlannedScenario:
    scenario: CommonScenario
    disposition: ScenarioDisposition
    min_fidelity: EvidenceFidelity
    reasons: tuple[str, ...]

    def as_dict(self) -> dict[str, Any]:
        return {
            "scenario": self.scenario.value,
            "disposition": self.disposition.value,
            "minimum_fidelity": self.min_fidelity.label,
            "reasons": list(self.reasons),
        }


@dataclass(frozen=True)
class VendorTestPlan:
    backend: TestBackendSpec
    scenarios: tuple[PlannedScenario, ...]
    plan_sha256: str

    def runnable(self) -> tuple[CommonScenario, ...]:
        return tuple(item.scenario for item in self.scenarios if item.disposition is ScenarioDisposition.RUN)

    def deferred(self) -> tuple[CommonScenario, ...]:
        return tuple(item.scenario for item in self.scenarios if item.disposition is ScenarioDisposition.DEFERRED)

    def as_dict(self) -> dict[str, Any]:
        runnable = [item.scenario.value for item in self.scenarios if item.disposition is ScenarioDisposition.RUN]
        deferred = [item.scenario.value for item in self.scenarios if item.disposition is ScenarioDisposition.DEFERRED]
        software_deferred = [
            item.scenario.value
            for item in self.scenarios
            if item.disposition is ScenarioDisposition.DEFERRED
            and not _REQUIREMENT_BY_SCENARIO[item.scenario].requires_hardware
        ]
        hardware_items = [
            item
            for item in self.scenarios
            if _REQUIREMENT_BY_SCENARIO[item.scenario].requires_hardware
        ]
        payload = {
            "schema_version": "network-device-test-plan/1",
            "backend": self.backend.as_dict(),
            "scenarios": [item.as_dict() for item in self.scenarios],
            "runnable_scenarios": runnable,
            "deferred_scenarios": deferred,
            "software_plan_fully_runnable": not software_deferred,
            "hardware_certification_possible": bool(hardware_items)
            and all(item.disposition is ScenarioDisposition.RUN for item in hardware_items),
            "production_writer_available": False,
            "write_authorized": False,
        }
        payload["plan_sha256"] = self.plan_sha256
        return payload


def _normalize_requested(
    requested: Iterable[CommonScenario | str] | None,
) -> tuple[CommonScenario, ...]:
    if requested is None:
        return tuple(item.scenario for item in SCENARIO_REQUIREMENTS)
    chosen = {
        item if isinstance(item, CommonScenario) else CommonScenario(str(item))
        for item in requested
    }
    return tuple(item.scenario for item in SCENARIO_REQUIREMENTS if item.scenario in chosen)


def plan_vendor_tests(
    backend: TestBackendSpec,
    requested: Iterable[CommonScenario | str] | None = None,
) -> VendorTestPlan:
    backend.validate()
    planned: list[PlannedScenario] = []

    for scenario in _normalize_requested(requested):
        requirement = _REQUIREMENT_BY_SCENARIO[scenario]
        reasons: list[str] = []
        if backend.fidelity < requirement.min_fidelity:
            reasons.append(
                f"requires {requirement.min_fidelity.label} fidelity; backend provides {backend.fidelity.label}"
            )
        missing = sorted(set(requirement.required_capabilities) - set(backend.capabilities))
        if missing:
            reasons.append("missing capabilities: " + ", ".join(missing))
        if requirement.requires_hardware and (
            backend.kind is not BackendKind.PHYSICAL_DEVICE or not backend.hardware_present
        ):
            reasons.append("requires a physical device")
        if requirement.requires_disposable_target and not backend.lab_disposable:
            reasons.append("scenario requires a declared lab/disposable target")
        if requirement.requires_fault_injection and not backend.fault_injection_allowed:
            reasons.append("fault injection is not enabled for this backend")
        if requirement.requires_snapshot_restore and not backend.snapshot_restore_available:
            reasons.append("snapshot/restore recovery is unavailable")

        planned.append(
            PlannedScenario(
                scenario=scenario,
                disposition=ScenarioDisposition.DEFERRED if reasons else ScenarioDisposition.RUN,
                min_fidelity=requirement.min_fidelity,
                reasons=tuple(reasons),
            )
        )

    unsigned = {
        "schema_version": "network-device-test-plan/1",
        "backend": backend.as_dict(),
        "scenarios": [item.as_dict() for item in planned],
        "production_writer_available": False,
        "write_authorized": False,
    }
    return VendorTestPlan(
        backend=backend,
        scenarios=tuple(planned),
        plan_sha256=_canonical_sha256(unsigned),
    )


@dataclass(frozen=True)
class ScenarioResult:
    scenario: CommonScenario
    passed: bool
    evidence_ref: str
    fidelity: EvidenceFidelity

    @classmethod
    def build(
        cls,
        *,
        scenario: CommonScenario | str,
        passed: bool,
        evidence_ref: str,
        fidelity: EvidenceFidelity | int,
    ) -> "ScenarioResult":
        ref = str(evidence_ref or "").strip()
        if not ref or any(marker in ref.lower() for marker in _FORBIDDEN_REF_MARKERS):
            raise ValueError("evidence_ref must be an opaque non-secret reference")
        return cls(
            scenario=scenario if isinstance(scenario, CommonScenario) else CommonScenario(str(scenario)),
            passed=bool(passed),
            evidence_ref=ref,
            fidelity=fidelity if isinstance(fidelity, EvidenceFidelity) else EvidenceFidelity(int(fidelity)),
        )


@dataclass(frozen=True)
class AcceptanceAssessment:
    payload: Mapping[str, Any]

    def as_dict(self) -> dict[str, Any]:
        return dict(self.payload)


def evaluate_vendor_test_results(
    plan: VendorTestPlan,
    results: Iterable[ScenarioResult],
) -> AcceptanceAssessment:
    by_scenario: dict[CommonScenario, ScenarioResult] = {}
    for result in results:
        if result.scenario in by_scenario:
            raise ValueError(f"duplicate result for {result.scenario.value}")
        by_scenario[result.scenario] = result

    runnable = {
        item.scenario: item
        for item in plan.scenarios
        if item.disposition is ScenarioDisposition.RUN
    }
    deferred = {
        item.scenario
        for item in plan.scenarios
        if item.disposition is ScenarioDisposition.DEFERRED
    }

    unexpected = sorted(item.value for item in by_scenario if item not in runnable)
    if unexpected:
        raise ValueError("results supplied for non-runnable scenarios: " + ", ".join(unexpected))

    missing = sorted(item.value for item in runnable if item not in by_scenario)
    if missing:
        raise ValueError("missing results for runnable scenarios: " + ", ".join(missing))

    result_payload: list[dict[str, Any]] = []
    for scenario, planned in runnable.items():
        result = by_scenario[scenario]
        if result.fidelity < planned.min_fidelity:
            raise ValueError(
                f"{scenario.value} evidence fidelity is below the scenario minimum"
            )
        if result.fidelity > plan.backend.fidelity:
            raise ValueError(
                f"{scenario.value} evidence fidelity exceeds backend fidelity"
            )
        result_payload.append(
            {
                "scenario": scenario.value,
                "passed": result.passed,
                "evidence_ref": result.evidence_ref,
                "fidelity": result.fidelity.label,
            }
        )

    software_scenarios = {
        item.scenario
        for item in plan.scenarios
        if not _REQUIREMENT_BY_SCENARIO[item.scenario].requires_hardware
    }
    deferred_software = software_scenarios & deferred
    software_passed = (
        bool(software_scenarios)
        and not deferred_software
        and all(by_scenario[item].passed for item in software_scenarios if item in by_scenario)
        and software_scenarios.issubset(by_scenario)
    )

    hardware_scenarios = {
        item.scenario
        for item in plan.scenarios
        if _REQUIREMENT_BY_SCENARIO[item.scenario].requires_hardware
    }
    hardware_certified = (
        bool(hardware_scenarios)
        and not (hardware_scenarios & deferred)
        and hardware_scenarios.issubset(by_scenario)
        and all(by_scenario[item].passed for item in hardware_scenarios)
    )

    payload = {
        "schema_version": "network-device-test-assessment/1",
        "plan_sha256": plan.plan_sha256,
        "vendor": plan.backend.vendor,
        "backend_id": plan.backend.backend_id,
        "backend_kind": plan.backend.kind.value,
        "backend_fidelity": plan.backend.fidelity.label,
        "results": result_payload,
        "deferred_scenarios": sorted(item.value for item in deferred),
        "deferred_software_scenarios": sorted(item.value for item in deferred_software),
        "software_acceptance_passed": software_passed,
        "hardware_certified": hardware_certified,
        "production_writer_available": False,
        "write_authorized": False,
    }
    payload["assessment_sha256"] = _canonical_sha256(payload)
    return AcceptanceAssessment(payload)


class VendorTestExecutor(Protocol):
    """Vendor-isolated execution boundary for the shared test harness.

    Implementations may own vendor-specific VM/controller/simulator/physical-device
    mechanics, but the common runner decides which scenarios are eligible. The
    protocol intentionally exposes no credential or production-authorization field.
    """

    vendor: str
    backend_id: str

    def run_scenario(self, scenario: CommonScenario) -> ScenarioResult:
        ...


def execute_vendor_test_plan(
    plan: VendorTestPlan,
    executor: VendorTestExecutor,
) -> AcceptanceAssessment:
    """Execute only RUN scenarios and evaluate the resulting evidence.

    The executor must be bound to the same vendor family and backend identity as
    the deterministic plan. Deferred scenarios are never sent to the executor.
    """

    if canonical_vendor(executor.vendor) != plan.backend.vendor:
        raise ValueError("executor vendor does not match the test plan")
    if str(executor.backend_id) != plan.backend.backend_id:
        raise ValueError("executor backend_id does not match the test plan")

    results: list[ScenarioResult] = []
    for item in plan.scenarios:
        if item.disposition is not ScenarioDisposition.RUN:
            continue
        result = executor.run_scenario(item.scenario)
        if result.scenario is not item.scenario:
            raise ValueError(
                f"executor returned {result.scenario.value} while {item.scenario.value} was requested"
            )
        results.append(result)

    return evaluate_vendor_test_results(plan, results)
