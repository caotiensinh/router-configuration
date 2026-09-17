"""Truthful evidence boundary for Cisco simulation-only validation.

Simulation can prove deterministic logic and integration behavior inside the
simulator's declared fidelity. It cannot prove physical Cisco hardware,
production deployment, or vendor-golden behavior. This module makes that
boundary machine-readable and fail-closed.
"""

from __future__ import annotations

import hashlib
import json
import re
from typing import Any, Iterable, Mapping

SIMULATION_EVIDENCE_SCHEMA = "cisco-simulation-evidence/1"
SIMULATION_EVIDENCE_ORIGIN = "network_sandbox_runtime"
SIMULATION_SCOPE = "simulation_logic_only"
PHYSICAL_LIMITATION_REASON = "physical_hardware_unavailable"
SIMULATION_LIMITATION_DISCLOSURE = (
    "Simulation/logic validation only. Physical Cisco hardware validation was "
    "not performed because physical hardware is unavailable in this environment."
)

# These are the only environment classes this simulation-only evidence path may claim.
# Physical hardware and production deliberately have separate evidence paths.
_ALLOWED_ENVIRONMENT_KINDS = frozenset(
    {
        "simulation",
        "deterministic_simulation",
        "qualified_simulation",
        "realistic_open_emulation",
    }
)

# These canonical acceptance gates require evidence that a simulator cannot create.
_FORBIDDEN_ACCEPTANCE_GATES = frozenset(
    {
        "C11.physical_evidence",
        "C11.physical_repository_acceptance",
        "C12.verified_production_deployment",
        "C12.final_handover_acceptance",
    }
)
_HEX40 = re.compile(r"^[0-9a-f]{40}$")
_HEX64 = re.compile(r"^[0-9a-f]{64}$")


class CiscoSimulationEvidenceError(ValueError):
    """Raised when simulation evidence overstates what was actually validated."""


def _canonical_sha256(value: object) -> str:
    raw = json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        default=str,
    ).encode("utf-8")
    return hashlib.sha256(raw).hexdigest()


def _require_sha(value: object, *, length: int, label: str) -> str:
    text = str(value or "").strip().lower()
    pattern = _HEX40 if length == 40 else _HEX64
    if not pattern.fullmatch(text):
        raise CiscoSimulationEvidenceError(
            f"{label} must be a {length}-character lowercase Git/SHA digest"
        )
    return text


def _require_text(value: object, *, label: str) -> str:
    text = str(value or "").strip()
    if not text:
        raise CiscoSimulationEvidenceError(f"{label} must be non-empty")
    return text


def _clean_strings(values: Iterable[object], *, label: str) -> list[str]:
    cleaned: list[str] = []
    for value in values:
        text = str(value or "").strip()
        if not text:
            raise CiscoSimulationEvidenceError(f"{label} entries must be non-empty")
        cleaned.append(text)
    if not cleaned:
        raise CiscoSimulationEvidenceError(f"{label} must not be empty")
    return cleaned


def build_simulation_evidence(
    *,
    source_sha: str,
    simulator_sha: str,
    simulation_profile: str,
    scenario_digest: str,
    input_digest: str,
    pre_state_digest: str,
    post_state_digest: str,
    environment_kind: str,
    tested_logic: Iterable[str],
    evidence_refs: Iterable[str],
    simulator_repository: str = "caotiensinh/Network_Sandbox_Runtime",
) -> dict[str, Any]:
    """Build evidence that explicitly identifies itself as simulation-only.

    Cross-repository evidence is reproducible only when the exact source revisions,
    simulation profile, scenario/input digests and pre/post state digests are bound
    into the signed record. The returned record deliberately cannot claim canonical
    physical or production acceptance. A separate real-device evidence path is
    required for those gates.
    """

    source_sha_value = _require_sha(source_sha, length=40, label="source_sha")
    simulator_sha_value = _require_sha(
        simulator_sha, length=40, label="simulator.source_sha"
    )
    environment_kind_value = _require_text(
        environment_kind, label="environment_kind"
    )
    if environment_kind_value not in _ALLOWED_ENVIRONMENT_KINDS:
        raise CiscoSimulationEvidenceError(
            "environment_kind must identify a simulation/emulation environment"
        )

    record: dict[str, Any] = {
        "schema_version": SIMULATION_EVIDENCE_SCHEMA,
        "evidence_origin": SIMULATION_EVIDENCE_ORIGIN,
        "evidence_scope": SIMULATION_SCOPE,
        "source_sha": source_sha_value,
        "simulator": {
            "repository": str(simulator_repository).strip(),
            "source_sha": simulator_sha_value,
        },
        # Explicit cross-repository provenance. Keep the legacy source/simulator
        # fields above for compatibility while validating that both views agree.
        "router_configuration_sha": source_sha_value,
        "network_sandbox_sha": simulator_sha_value,
        "simulation_profile": _require_text(
            simulation_profile, label="simulation_profile"
        ),
        "scenario_digest": _require_sha(
            scenario_digest, length=64, label="scenario_digest"
        ),
        "input_digest": _require_sha(
            input_digest, length=64, label="input_digest"
        ),
        "pre_state_digest": _require_sha(
            pre_state_digest, length=64, label="pre_state_digest"
        ),
        "post_state_digest": _require_sha(
            post_state_digest, length=64, label="post_state_digest"
        ),
        "environment_kind": environment_kind_value,
        "tested_logic": _clean_strings(tested_logic, label="tested_logic"),
        "evidence_refs": _clean_strings(evidence_refs, label="evidence_refs"),
        "physical_validation_performed": False,
        "physical_device_verified": False,
        "physical_validation_blocked_reason": PHYSICAL_LIMITATION_REASON,
        "production_validation_performed": False,
        "production_write_authorized": False,
        "canonical_acceptance_promoted": False,
        "claimed_acceptance_gates": [],
        "limitations": [SIMULATION_LIMITATION_DISCLOSURE],
    }
    if not record["simulator"]["repository"]:
        raise CiscoSimulationEvidenceError("simulator.repository must be non-empty")
    record["record_sha256"] = _canonical_sha256(record)
    validate_simulation_evidence(record)
    return record


def validate_simulation_evidence(payload: Mapping[str, Any]) -> None:
    """Reject any simulation record that is ambiguous or elevated to real evidence."""

    if payload.get("schema_version") != SIMULATION_EVIDENCE_SCHEMA:
        raise CiscoSimulationEvidenceError("unexpected simulation evidence schema")
    if payload.get("evidence_origin") != SIMULATION_EVIDENCE_ORIGIN:
        raise CiscoSimulationEvidenceError("unexpected simulation evidence origin")
    if payload.get("evidence_scope") != SIMULATION_SCOPE:
        raise CiscoSimulationEvidenceError("simulation evidence scope must be explicit")

    source_sha = _require_sha(payload.get("source_sha"), length=40, label="source_sha")
    simulator = payload.get("simulator")
    if not isinstance(simulator, Mapping):
        raise CiscoSimulationEvidenceError("simulator metadata is required")
    if not str(simulator.get("repository") or "").strip():
        raise CiscoSimulationEvidenceError("simulator.repository must be non-empty")
    simulator_sha = _require_sha(
        simulator.get("source_sha"), length=40, label="simulator.source_sha"
    )

    # Fail closed on incomplete or internally inconsistent provenance. These fields
    # make cross-repository Network_Sandbox_Runtime evidence reproducible instead of
    # merely asserting that a simulator ran.
    if _require_sha(
        payload.get("router_configuration_sha"),
        length=40,
        label="router_configuration_sha",
    ) != source_sha:
        raise CiscoSimulationEvidenceError(
            "router_configuration_sha must match source_sha"
        )
    if _require_sha(
        payload.get("network_sandbox_sha"),
        length=40,
        label="network_sandbox_sha",
    ) != simulator_sha:
        raise CiscoSimulationEvidenceError(
            "network_sandbox_sha must match simulator.source_sha"
        )
    _require_text(payload.get("simulation_profile"), label="simulation_profile")
    for field in (
        "scenario_digest",
        "input_digest",
        "pre_state_digest",
        "post_state_digest",
    ):
        _require_sha(payload.get(field), length=64, label=field)
    environment_kind = _require_text(
        payload.get("environment_kind"), label="environment_kind"
    )
    if environment_kind not in _ALLOWED_ENVIRONMENT_KINDS:
        raise CiscoSimulationEvidenceError(
            "environment_kind must identify a simulation/emulation environment"
        )

    for field in (
        "physical_validation_performed",
        "physical_device_verified",
        "production_validation_performed",
        "production_write_authorized",
        "canonical_acceptance_promoted",
    ):
        if payload.get(field) is not False:
            raise CiscoSimulationEvidenceError(
                f"simulation evidence requires {field}=false"
            )

    if payload.get("physical_validation_blocked_reason") != PHYSICAL_LIMITATION_REASON:
        raise CiscoSimulationEvidenceError(
            "simulation evidence must record the physical-hardware limitation"
        )

    limitations = payload.get("limitations")
    if not isinstance(limitations, list) or SIMULATION_LIMITATION_DISCLOSURE not in limitations:
        raise CiscoSimulationEvidenceError(
            "simulation evidence must disclose that physical Cisco hardware was not tested"
        )

    tested_logic = payload.get("tested_logic")
    evidence_refs = payload.get("evidence_refs")
    if not isinstance(tested_logic, list) or not tested_logic or not all(
        isinstance(item, str) and item.strip() for item in tested_logic
    ):
        raise CiscoSimulationEvidenceError("tested_logic must contain explicit logic coverage")
    if not isinstance(evidence_refs, list) or not evidence_refs or not all(
        isinstance(item, str) and item.strip() for item in evidence_refs
    ):
        raise CiscoSimulationEvidenceError("evidence_refs must contain explicit evidence")

    claims = payload.get("claimed_acceptance_gates")
    if not isinstance(claims, list):
        raise CiscoSimulationEvidenceError("claimed_acceptance_gates must be a list")
    forbidden = _FORBIDDEN_ACCEPTANCE_GATES.intersection(str(item) for item in claims)
    if forbidden:
        raise CiscoSimulationEvidenceError(
            "simulation evidence cannot satisfy physical/production gates: "
            + ", ".join(sorted(forbidden))
        )
    if claims:
        raise CiscoSimulationEvidenceError(
            "simulation evidence cannot promote canonical acceptance gates"
        )

    recorded_digest = _require_sha(
        payload.get("record_sha256"), length=64, label="record_sha256"
    )
    body = dict(payload)
    body.pop("record_sha256", None)
    if recorded_digest != _canonical_sha256(body):
        raise CiscoSimulationEvidenceError("simulation evidence digest mismatch")


def simulation_scope_status() -> dict[str, Any]:
    """Expose the invariant for reports and tests without creating acceptance evidence."""

    return {
        "evidence_scope": SIMULATION_SCOPE,
        "logic_simulation_allowed": True,
        "physical_validation_performed": False,
        "physical_device_verified": False,
        "physical_validation_blocked_reason": PHYSICAL_LIMITATION_REASON,
        "production_validation_performed": False,
        "production_write_authorized": False,
        "canonical_acceptance_promoted": False,
        "disclosure": SIMULATION_LIMITATION_DISCLOSURE,
    }
