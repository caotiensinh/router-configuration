from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from typing import Any, Mapping


class FailureScenario(str, Enum):
    INTERNET_DOWN_LINK_UP = "internet_down_link_up"
    DNS_FAILURE = "dns_failure"
    DEFAULT_ROUTE_LOSS = "default_route_loss"


@dataclass(frozen=True)
class FailureScenarioAssessment:
    scenario: FailureScenario
    observed: bool
    rollback_required: bool
    required_recovery_checks: tuple[str, ...]
    observations: Mapping[str, bool]

    def as_dict(self) -> dict[str, Any]:
        return {
            "schema_version": "routeros-failure-scenario-assessment/1",
            "scenario": self.scenario.value,
            "observed": self.observed,
            "rollback_required": self.rollback_required,
            "required_recovery_checks": list(self.required_recovery_checks),
            "observations": dict(self.observations),
            "production_writer_available": False,
            "write_authorized": False,
        }


_REQUIRED = {
    FailureScenario.INTERNET_DOWN_LINK_UP: {
        "link_running": True,
        "internet_reachable": False,
        "management_reachable": True,
    },
    FailureScenario.DNS_FAILURE: {
        "public_ip_reachable": True,
        "dns_resolution_ok": False,
        "management_reachable": True,
    },
    FailureScenario.DEFAULT_ROUTE_LOSS: {
        "default_route_usable": False,
        "management_reachable": True,
    },
}

_RECOVERY = {
    FailureScenario.INTERNET_DOWN_LINK_UP: (
        "management_recovered",
        "internet_recovered",
        "managed_objects_reconciled",
    ),
    FailureScenario.DNS_FAILURE: (
        "management_recovered",
        "dns_recovered",
        "managed_objects_reconciled",
    ),
    FailureScenario.DEFAULT_ROUTE_LOSS: (
        "management_recovered",
        "routing_recovered",
        "managed_objects_reconciled",
    ),
}


def assess_failure_scenario(
    scenario: FailureScenario | str,
    observations: Mapping[str, Any],
) -> FailureScenarioAssessment:
    try:
        kind = scenario if isinstance(scenario, FailureScenario) else FailureScenario(str(scenario))
    except ValueError as exc:
        raise ValueError(f"unsupported failure scenario: {scenario}") from exc
    if not isinstance(observations, Mapping):
        raise ValueError("observations must be an object")

    required = _REQUIRED[kind]
    normalized: dict[str, bool] = {}
    for key, expected in required.items():
        value = observations.get(key)
        if not isinstance(value, bool):
            raise ValueError(f"{kind.value} requires boolean observation: {key}")
        normalized[key] = value
    observed = all(normalized[key] is expected for key, expected in required.items())

    return FailureScenarioAssessment(
        scenario=kind,
        observed=observed,
        rollback_required=observed,
        required_recovery_checks=_RECOVERY[kind],
        observations=normalized,
    )
