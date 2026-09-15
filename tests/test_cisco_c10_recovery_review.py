import hashlib
import json
import unittest
from dataclasses import replace

from router_configuration.vendors.cisco.c10_recovery_review import (
    CiscoC10RecoveryReviewError,
    build_c10_recovery_review_candidate,
)
from router_configuration.vendors.cisco.recovery_observation import CiscoRecoveryObservation


def observation(outcome="automatic_rollback"):
    phases = ("lock_running_datastore", "apply_exact_approved_candidate", "verify_recovered_management_connectivity_and_prechange_state")
    unsigned = {
        "schema_version": "cisco-c10-recovery-observation/1",
        "target_id": "c8kv-lab-01",
        "model": "C8000V",
        "iosxe_version": "17.18.1a",
        "source_sha": "1" * 40,
        "source_run_id": "run-c10-1",
        "recovery_plan_sha256": "2" * 64,
        "execution_contract_sha256": "3" * 64,
        "outcome": outcome,
        "observed_phase_order": list(phases),
        "candidate_claims_live_execution": True,
        "candidate_claims_live_rollback": outcome == "automatic_rollback",
        "candidate_claims_restored_state_verified": outcome == "automatic_rollback",
        "repository_live_evidence_accepted": False,
        "c10_complete": False,
        "physical_device_verified": False,
        "production_writer_available": False,
        "production_write_authorized": False,
    }
    digest = hashlib.sha256(json.dumps(unsigned, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")).hexdigest()
    return CiscoRecoveryObservation(
        target_id="c8kv-lab-01",
        model="C8000V",
        iosxe_version="17.18.1a",
        source_sha="1" * 40,
        source_run_id="run-c10-1",
        recovery_plan_sha256="2" * 64,
        execution_contract_sha256="3" * 64,
        outcome=outcome,
        observed_phase_order=phases,
        observation_sha256=digest,
        candidate_claims_live_execution=True,
        candidate_claims_live_rollback=outcome == "automatic_rollback",
        candidate_claims_restored_state_verified=outcome == "automatic_rollback",
    )


class CiscoC10RecoveryReviewTests(unittest.TestCase):
    def test_rollback_candidate_is_non_promoting(self):
        result = build_c10_recovery_review_candidate(
            observation(),
            review_id="REV-C10-001",
            reviewer_ref="lab:reviewer-01",
            reviewer_attestation_sha256="a" * 64,
        )
        self.assertTrue(result["eligible_for_repository_acceptance"])
        self.assertEqual(result["outcome"], "automatic_rollback")
        self.assertFalse(result["repository_live_evidence_accepted"])
        self.assertFalse(result["c10_complete"])
        self.assertFalse(result["production_write_authorized"])

    def test_tampered_observation_digest_is_rejected(self):
        broken = replace(observation(), observation_sha256="9" * 64)
        with self.assertRaisesRegex(CiscoC10RecoveryReviewError, "digest mismatch"):
            build_c10_recovery_review_candidate(
                broken,
                review_id="REV-C10-001",
                reviewer_ref="lab:reviewer-01",
                reviewer_attestation_sha256="a" * 64,
            )

    def test_incomplete_rollback_claim_is_rejected(self):
        broken = replace(observation(), candidate_claims_restored_state_verified=False)
        payload = broken.as_dict()
        payload.pop("observation_sha256")
        broken = replace(broken, observation_sha256=hashlib.sha256(json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")).hexdigest())
        with self.assertRaisesRegex(CiscoC10RecoveryReviewError, "restored state"):
            build_c10_recovery_review_candidate(
                broken,
                review_id="REV-C10-001",
                reviewer_ref="lab:reviewer-01",
                reviewer_attestation_sha256="a" * 64,
            )


if __name__ == "__main__":
    unittest.main()
