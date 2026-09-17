from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from typing import Any

from router_configuration.test_harness import (
    AcceptanceAssessment,
    EvidenceFidelity,
    ScenarioDisposition,
    VendorTestPlan,
)


class HardwareAcceptanceStatus(str, Enum):
    """Explicit status for hardware-only validation.

    Hardware absence is an external validation limitation, not a software failure.
    This status must never be used to promote virtual or vendor-OS evidence to
    physical-device certification.
    """

    NOT_REQUESTED = "not_requested"
    DEFERRED_EXTERNAL_HARDWARE = "deferred_external_hardware"
    READY = "ready"
    VERIFIED = "verified"
    FAILED = "failed"
    BLOCKED = "blocked"


@dataclass(frozen=True)
class ValidationScopeSummary:
    hardware_acceptance_status: HardwareAcceptanceStatus
    software_acceptance_passed: bool | None
    hardware_certified: bool
    hardware_blocks_software_completion: bool
    physical_certification_claimed: bool

    def as_dict(self) -> dict[str, Any]:
        return {
            "schema_version": "validation-scope-summary/1",
            "hardware_acceptance_status": self.hardware_acceptance_status.value,
            "software_acceptance_passed": self.software_acceptance_passed,
            "hardware_certified": self.hardware_certified,
            "hardware_blocks_software_completion": self.hardware_blocks_software_completion,
            "physical_certification_claimed": self.physical_certification_claimed,
        }


def _hardware_items(plan: VendorTestPlan):
    """Return scenarios whose minimum accepted evidence is physical fidelity."""

    return tuple(
        item
        for item in plan.scenarios
        if item.min_fidelity is EvidenceFidelity.PHYSICAL
    )


def classify_hardware_plan(plan: VendorTestPlan) -> HardwareAcceptanceStatus:
    """Classify the hardware-validation state before result evaluation.

    A non-physical backend with physical-only scenarios is classified as an
    external hardware deferral. Missing software capabilities remain ordinary
    plan blockers and are not mislabeled as hardware absence.
    """

    hardware_items = _hardware_items(plan)
    if not hardware_items:
        return HardwareAcceptanceStatus.NOT_REQUESTED

    if all(item.disposition is ScenarioDisposition.RUN for item in hardware_items):
        return HardwareAcceptanceStatus.READY

    if not plan.backend.hardware_present:
        return HardwareAcceptanceStatus.DEFERRED_EXTERNAL_HARDWARE

    return HardwareAcceptanceStatus.BLOCKED


def summarize_validation_scope(
    plan: VendorTestPlan,
    assessment: AcceptanceAssessment | None = None,
) -> ValidationScopeSummary:
    """Produce a fail-closed software-vs-hardware acceptance summary.

    Hardware absence never turns a passing software scope into failure and never
    creates a physical certification claim. Physical verification can only be
    reported after a physical-fidelity plan was runnable and its evaluated
    hardware scenarios passed.
    """

    planned_status = classify_hardware_plan(plan)
    if assessment is None:
        return ValidationScopeSummary(
            hardware_acceptance_status=planned_status,
            software_acceptance_passed=None,
            hardware_certified=False,
            hardware_blocks_software_completion=False,
            physical_certification_claimed=False,
        )

    payload = assessment.as_dict()
    software_passed = bool(payload.get("software_acceptance_passed", False))
    hardware_certified = bool(payload.get("hardware_certified", False))

    if planned_status is HardwareAcceptanceStatus.READY:
        hardware_status = (
            HardwareAcceptanceStatus.VERIFIED
            if hardware_certified
            else HardwareAcceptanceStatus.FAILED
        )
    else:
        hardware_status = planned_status

    return ValidationScopeSummary(
        hardware_acceptance_status=hardware_status,
        software_acceptance_passed=software_passed,
        hardware_certified=hardware_certified,
        hardware_blocks_software_completion=False,
        physical_certification_claimed=(
            hardware_status is HardwareAcceptanceStatus.VERIFIED
            and hardware_certified
        ),
    )
