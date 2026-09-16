import hashlib
import json
import unittest
from dataclasses import replace

from router_configuration.vendors.cisco.recovery_observation import CiscoRecoveryObservation
from router_configuration.vendors.cisco.restored_state_verifier import (
    CiscoRestoredStateVerifierError,
    verify_restored_state_candidate,
)

PHASES = tuple(f"phase-{n}" for n in range(1, 14))


def canonical_sha256(value):
    return hashlib.sha256(
        json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
    ).hexdigest()


def observation():
    fields = {
        "schema_version": "cisco-c10-recovery-observation/1",
        "target_id": "lab-router-1",
        "model": "C8000V",
        "iosxe_version": "17.18.1a",
        "source_sha": "1" * 40,
        "source_run_id": "run-123",
        "recovery_plan_sha256": "2" * 64,
        "execution_contract_sha256": "3" * 64,
        "outcome": "automatic_rollback",
        "observed_phase_order": list(PHASES),
        "candidate_claims_live_execution": True,
        "candidate_claims_live_rollback": True,
        "candidate_claims_restored_state_verified": True,
        "repository_live_evidence_accepted": False,
        "c10_complete": False,
        "physical_device_verified": False,
        "production_writer_available": False,
        "production_write_authorized": False,
    }
    return CiscoRecoveryObservation(
        target_id=fields["target_id"],
        model=fields["model"],
        iosxe_version=fields["iosxe_version"],
        source_sha=fields["source_sha"],
        source_run_id=fields["source_run_id"],
        recovery_plan_sha256=fields["recovery_plan_sha256"],
        execution_contract_sha256=fields["execution_contract_sha256"],
        outcome=fields["outcome"],
        observed_phase_order=PHASES,
        observation_sha256=canonical_sha256(fields),
        candidate_claims_live_execution=True,
        candidate_claims_live_rollback=True,
        candidate_claims_restored_state_verified=True,
    )


class CiscoRestoredStateVerifierTests(unittest.TestCase):
    def test_matching_state_and_management_baselines_are_non_promoting(self):
        obs = observation()
        first = verify_restored_state_candidate(
            obs,
            pre_state_sha256="a" * 64,
            post_state_sha256="a" * 64,
            pre_management_sha256="b" * 64,
            post_management_sha256="b" * 64,
        )
        second = verify_restored_state_candidate(
            obs,
            pre_state_sha256="a" * 64,
            post_state_sha256="a" * 64,
            pre_management_sha256="b" * 64,
            post_management_sha256="b" * 64,
        )
        self.assertEqual(first, second)
        self.assertTrue(first["normalized_state_restored"])
        self.assertTrue(first["management_state_restored"])
        self.assertFalse(first["repository_live_evidence_accepted"])
        self.assertFalse(first["c10_complete"])
        self.assertFalse(first["production_write_authorized"])

    def test_state_or_management_mismatch_fails_closed(self):
        obs = observation()
        with self.assertRaisesRegex(CiscoRestoredStateVerifierError, "normalized state"):
            verify_restored_state_candidate(
                obs,
                pre_state_sha256="a" * 64,
                post_state_sha256="c" * 64,
                pre_management_sha256="b" * 64,
                post_management_sha256="b" * 64,
            )
        with self.assertRaisesRegex(CiscoRestoredStateVerifierError, "management baseline"):
            verify_restored_state_candidate(
                obs,
                pre_state_sha256="a" * 64,
                post_state_sha256="a" * 64,
                pre_management_sha256="b" * 64,
                post_management_sha256="c" * 64,
            )

    def test_tampered_observation_and_nonrollback_outcome_fail_closed(self):
        with self.assertRaisesRegex(CiscoRestoredStateVerifierError, "digest mismatch"):
            verify_restored_state_candidate(
                replace(observation(), observation_sha256="0" * 64),
                pre_state_sha256="a" * 64,
                post_state_sha256="a" * 64,
                pre_management_sha256="b" * 64,
                post_management_sha256="b" * 64,
            )
        obs = replace(observation(), outcome="confirmed")
        unsigned = {
            "schema_version": "cisco-c10-recovery-observation/1",
            "target_id": obs.target_id,
            "model": obs.model,
            "iosxe_version": obs.iosxe_version,
            "source_sha": obs.source_sha,
            "source_run_id": obs.source_run_id,
            "recovery_plan_sha256": obs.recovery_plan_sha256,
            "execution_contract_sha256": obs.execution_contract_sha256,
            "outcome": obs.outcome,
            "observed_phase_order": list(obs.observed_phase_order),
            "candidate_claims_live_execution": obs.candidate_claims_live_execution,
            "candidate_claims_live_rollback": obs.candidate_claims_live_rollback,
            "candidate_claims_restored_state_verified": obs.candidate_claims_restored_state_verified,
            "repository_live_evidence_accepted": False,
            "c10_complete": False,
            "physical_device_verified": False,
            "production_writer_available": False,
            "production_write_authorized": False,
        }
        obs = replace(obs, observation_sha256=canonical_sha256(unsigned))
        with self.assertRaisesRegex(CiscoRestoredStateVerifierError, "automatic_rollback"):
            verify_restored_state_candidate(
                obs,
                pre_state_sha256="a" * 64,
                post_state_sha256="a" * 64,
                pre_management_sha256="b" * 64,
                post_management_sha256="b" * 64,
            )


if __name__ == "__main__":
    unittest.main()
