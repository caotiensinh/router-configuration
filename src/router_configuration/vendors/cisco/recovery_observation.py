"""Fail-closed ingestion contract for observed Cisco C10 recovery executions.

This module validates the shape and binding of a future live observation artifact.
It never executes NETCONF and never converts an observation claim into accepted
repository evidence or production write authority.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass
import hashlib
import hmac
import json
import re
from typing import Any, Mapping

from .transaction_execution_contract import CiscoRecoveryExecutionContract

_SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
_GIT_SHA_RE = re.compile(r"^[0-9a-f]{40}$")
_RUN_ID_RE = re.compile(r"^[A-Za-z0-9_.:-]{1,96}$")
_ALLOWED_OUTCOMES = frozenset({"confirmed", "automatic_rollback"})


class CiscoRecoveryObservationError(ValueError):
    """Raised when a C10 recovery observation candidate fails closed."""


def _sha(value: object, label: str) -> str:
    text = str(value or "").strip().lower()
    if not _SHA256_RE.fullmatch(text):
        raise CiscoRecoveryObservationError(f"{label} must be lowercase SHA-256")
    return text


def _canonical_sha256(value: object) -> str:
    raw = json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
    return hashlib.sha256(raw).hexdigest()


@dataclass(frozen=True)
class CiscoRecoveryObservation:
    target_id: str
    model: str
    iosxe_version: str
    source_sha: str
    source_run_id: str
    recovery_plan_sha256: str
    execution_contract_sha256: str
    outcome: str
    observed_phase_order: tuple[str, ...]
    observation_sha256: str
    candidate_claims_live_execution: bool
    candidate_claims_live_rollback: bool
    candidate_claims_restored_state_verified: bool
    repository_live_evidence_accepted: bool = False
    c10_complete: bool = False
    physical_device_verified: bool = False
    production_writer_available: bool = False
    production_write_authorized: bool = False

    def as_dict(self) -> dict[str, Any]:
        payload = asdict(self)
        payload["observed_phase_order"] = list(self.observed_phase_order)
        payload["schema_version"] = "cisco-c10-recovery-observation/1"
        return payload


def validate_recovery_observation_candidate(
    payload: Mapping[str, Any],
    *,
    contract: CiscoRecoveryExecutionContract,
) -> CiscoRecoveryObservation:
    """Validate a future live observation artifact without accepting it as evidence."""

    if payload.get("schema_version") != "cisco-c10-live-recovery-observation/1":
        raise CiscoRecoveryObservationError("unexpected recovery observation schema")

    for field in ("repository_live_evidence_accepted", "c10_complete", "physical_device_verified", "production_writer_available", "production_write_authorized"):
        if payload.get(field) is not False:
            raise CiscoRecoveryObservationError(f"observation cannot self-promote: {field}")

    if payload.get("target_id") != contract.target_id:
        raise CiscoRecoveryObservationError("observation target differs from execution contract")
    if payload.get("model") != contract.model or payload.get("iosxe_version") != contract.iosxe_version:
        raise CiscoRecoveryObservationError("observation platform/version differs from execution contract")

    plan_digest = _sha(payload.get("recovery_plan_sha256"), "recovery_plan_sha256")
    contract_digest = _sha(payload.get("execution_contract_sha256"), "execution_contract_sha256")
    if not hmac.compare_digest(plan_digest, contract.recovery_plan_sha256):
        raise CiscoRecoveryObservationError("observation recovery plan digest mismatch")
    if not hmac.compare_digest(contract_digest, contract.contract_sha256):
        raise CiscoRecoveryObservationError("observation execution contract digest mismatch")

    source_sha = str(payload.get("source_sha", "")).strip().lower()
    if not _GIT_SHA_RE.fullmatch(source_sha):
        raise CiscoRecoveryObservationError("source_sha must be a 40-character Git SHA")
    source_run_id = str(payload.get("source_run_id", "")).strip()
    if not _RUN_ID_RE.fullmatch(source_run_id):
        raise CiscoRecoveryObservationError("source_run_id contains unsupported characters")

    outcome = str(payload.get("outcome", "")).strip()
    if outcome not in _ALLOWED_OUTCOMES:
        raise CiscoRecoveryObservationError("recovery observation outcome is unsupported")

    phases = payload.get("observed_phase_order")
    if not isinstance(phases, list) or tuple(phases) != contract.phase_order:
        raise CiscoRecoveryObservationError("observed recovery phase order differs from contract")

    live_execution = payload.get("live_execution_observed") is True
    live_rollback = payload.get("live_rollback_observed") is True
    restored = payload.get("restored_state_verified") is True
    if not live_execution:
        raise CiscoRecoveryObservationError("live_execution_observed must be true for a candidate live observation")
    if outcome == "confirmed" and live_rollback:
        raise CiscoRecoveryObservationError("confirmed outcome cannot also claim live rollback")
    if outcome == "automatic_rollback" and (not live_rollback or not restored):
        raise CiscoRecoveryObservationError("automatic rollback outcome requires observed rollback and restored-state verification")

    unsigned = {
        "schema_version": "cisco-c10-recovery-observation/1",
        "target_id": contract.target_id,
        "model": contract.model,
        "iosxe_version": contract.iosxe_version,
        "source_sha": source_sha,
        "source_run_id": source_run_id,
        "recovery_plan_sha256": plan_digest,
        "execution_contract_sha256": contract_digest,
        "outcome": outcome,
        "observed_phase_order": list(contract.phase_order),
        "candidate_claims_live_execution": live_execution,
        "candidate_claims_live_rollback": live_rollback,
        "candidate_claims_restored_state_verified": restored,
        "repository_live_evidence_accepted": False,
        "c10_complete": False,
        "physical_device_verified": False,
        "production_writer_available": False,
        "production_write_authorized": False,
    }
    return CiscoRecoveryObservation(
        target_id=contract.target_id,
        model=contract.model,
        iosxe_version=contract.iosxe_version,
        source_sha=source_sha,
        source_run_id=source_run_id,
        recovery_plan_sha256=plan_digest,
        execution_contract_sha256=contract_digest,
        outcome=outcome,
        observed_phase_order=contract.phase_order,
        observation_sha256=_canonical_sha256(unsigned),
        candidate_claims_live_execution=live_execution,
        candidate_claims_live_rollback=live_rollback,
        candidate_claims_restored_state_verified=restored,
    )
