import hashlib
import json
import unittest

from router_configuration.vendors.cisco.c10_acceptance_decision import (
    CiscoC10AcceptanceDecisionError,
    bind_c10_repository_decision,
)


def canonical_sha256(value):
    return hashlib.sha256(
        json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
    ).hexdigest()


def candidate(outcome="automatic_rollback"):
    item = {
        "schema_version": "cisco-c10-recovery-review-candidate/1",
        "review_id": "C10-REV-001",
        "reviewer_ref": "reviewer:recovery",
        "reviewer_attestation_sha256": "1" * 64,
        "target_id": "lab-router-01",
        "model": "C8000V",
        "iosxe_version": "17.18.1a",
        "observation_sha256": "2" * 64,
        "recovery_plan_sha256": "3" * 64,
        "execution_contract_sha256": "4" * 64,
        "outcome": outcome,
        "eligible_for_repository_acceptance": True,
        "repository_live_evidence_accepted": False,
        "c10_complete": False,
        "physical_device_verified": False,
        "production_writer_available": False,
        "production_write_authorized": False,
    }
    item["review_candidate_sha256"] = canonical_sha256(item)
    return item


class CiscoC10AcceptanceDecisionTests(unittest.TestCase):
    def test_accept_completes_recovery_gate_without_production_authority(self):
        for outcome in ("automatic_rollback", "confirmed"):
            result = bind_c10_repository_decision(
                candidate(outcome),
                decision_id=f"C10-DEC-{outcome}",
                authority_ref="authority:recovery-review",
                authority_attestation_sha256="5" * 64,
                decision="accept",
            )
            self.assertTrue(result["repository_live_evidence_accepted"])
            self.assertTrue(result["c10_complete"])
            self.assertFalse(result["production_writer_available"])
            self.assertFalse(result["production_write_authorized"])

    def test_reject_and_unknown_outcome_fail_safe(self):
        result = bind_c10_repository_decision(
            candidate(),
            decision_id="C10-DEC-REJECT",
            authority_ref="authority:recovery-review",
            authority_attestation_sha256="6" * 64,
            decision="reject",
        )
        self.assertFalse(result["c10_complete"])

        item = candidate("manual_override")
        with self.assertRaisesRegex(CiscoC10AcceptanceDecisionError, "unsupported C10 reviewed outcome"):
            bind_c10_repository_decision(
                item,
                decision_id="C10-DEC-BAD",
                authority_ref="authority:recovery-review",
                authority_attestation_sha256="7" * 64,
                decision="accept",
            )


if __name__ == "__main__":
    unittest.main()
