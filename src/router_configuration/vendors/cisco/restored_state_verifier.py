"""Cryptographic restored-state comparison for Cisco C10 rollback evidence.

This verifier accepts only an already validated automatic-rollback observation,
recomputes its observation digest, and compares pre/post normalized-state and
management baselines with constant-time SHA-256 equality. It does not accept the
evidence into the repository and never authorizes production write.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import re

from .recovery_observation import CiscoRecoveryObservation

_SHA256 = re.compile(r"^[0-9a-f]{64}$")


class CiscoRestoredStateVerifierError(ValueError):
    pass


def _canonical_sha256(value: object) -> str:
    return hashlib.sha256(
        json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
    ).hexdigest()


def _sha(value: object, label: str) -> str:
    text = str(value or "").strip().lower()
    if not _SHA256.fullmatch(text):
        raise CiscoRestoredStateVerifierError(f"{label} must be lowercase SHA-256")
    return text


def _verify_observation_digest(observation: CiscoRecoveryObservation) -> None:
    unsigned = {
        "schema_version": "cisco-c10-recovery-observation/1",
        "target_id": observation.target_id,
        "model": observation.model,
        "iosxe_version": observation.iosxe_version,
        "source_sha": observation.source_sha,
        "source_run_id": observation.source_run_id,
        "recovery_plan_sha256": observation.recovery_plan_sha256,
        "execution_contract_sha256": observation.execution_contract_sha256,
        "outcome": observation.outcome,
        "observed_phase_order": list(observation.observed_phase_order),
        "candidate_claims_live_execution": observation.candidate_claims_live_execution,
        "candidate_claims_live_rollback": observation.candidate_claims_live_rollback,
        "candidate_claims_restored_state_verified": observation.candidate_claims_restored_state_verified,
        "repository_live_evidence_accepted": observation.repository_live_evidence_accepted,
        "c10_complete": observation.c10_complete,
        "physical_device_verified": observation.physical_device_verified,
        "production_writer_available": observation.production_writer_available,
        "production_write_authorized": observation.production_write_authorized,
    }
    expected = _canonical_sha256(unsigned)
    actual = _sha(observation.observation_sha256, "observation_sha256")
    if not hmac.compare_digest(actual, expected):
        raise CiscoRestoredStateVerifierError("recovery observation digest mismatch")


def verify_restored_state_candidate(
    observation: CiscoRecoveryObservation,
    *,
    pre_state_sha256: str,
    post_state_sha256: str,
    pre_management_sha256: str,
    post_management_sha256: str,
) -> dict:
    if not isinstance(observation, CiscoRecoveryObservation):
        raise CiscoRestoredStateVerifierError("observation must be CiscoRecoveryObservation")
    _verify_observation_digest(observation)
    if observation.outcome != "automatic_rollback":
        raise CiscoRestoredStateVerifierError("restored-state verification requires automatic_rollback outcome")
    if not observation.candidate_claims_live_execution or not observation.candidate_claims_live_rollback:
        raise CiscoRestoredStateVerifierError("rollback observation lacks live execution/rollback claims")
    if not observation.candidate_claims_restored_state_verified:
        raise CiscoRestoredStateVerifierError("rollback observation lacks restored-state claim")
    for field in (
        "repository_live_evidence_accepted",
        "c10_complete",
        "physical_device_verified",
        "production_writer_available",
        "production_write_authorized",
    ):
        if getattr(observation, field) is not False:
            raise CiscoRestoredStateVerifierError(f"rollback observation crossed safety boundary: {field}")

    pre_state = _sha(pre_state_sha256, "pre_state_sha256")
    post_state = _sha(post_state_sha256, "post_state_sha256")
    pre_management = _sha(pre_management_sha256, "pre_management_sha256")
    post_management = _sha(post_management_sha256, "post_management_sha256")
    if not hmac.compare_digest(pre_state, post_state):
        raise CiscoRestoredStateVerifierError("normalized state was not restored to pre-change baseline")
    if not hmac.compare_digest(pre_management, post_management):
        raise CiscoRestoredStateVerifierError("management baseline was not restored")

    result = {
        "schema_version": "cisco-c10-restored-state-verification/1",
        "observation_sha256": observation.observation_sha256,
        "target_id": observation.target_id,
        "pre_state_sha256": pre_state,
        "post_state_sha256": post_state,
        "pre_management_sha256": pre_management,
        "post_management_sha256": post_management,
        "normalized_state_restored": True,
        "management_state_restored": True,
        "repository_live_evidence_accepted": False,
        "c10_complete": False,
        "production_write_authorized": False,
    }
    result["verification_record_sha256"] = _canonical_sha256(result)
    return result
