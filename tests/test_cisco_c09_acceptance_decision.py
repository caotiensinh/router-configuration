import hashlib
import json
import unittest

from router_configuration.vendors.cisco.c09_acceptance_decision import (
    CiscoC09AcceptanceDecisionError,
    bind_c09_repository_decision,
)


def canonical_sha256(value):
    return hashlib.sha256(
        json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
    ).hexdigest()


def candidate():
    item = {
        "schema_version": "cisco-c09-repository-review-candidate/1",
        "review_id": "C09-REV-001",
        "reviewer_ref": "reviewer:iosxe-lab",
        "reviewer_attestation_sha256": "1" * 64,
        "target_id": "c8000v-lab-01",
        "model": "C8000V",
        "iosxe_version": "17.18.1a",
        "ingest_record_sha256": "2" * 64,
        "validated_bundle_sha256": "3" * 64,
        "eligible_for_repository_acceptance": True,
        "repository_live_evidence_accepted": False,
        "c09_complete": False,
        "physical_hardware_claimed": False,
        "production_writer_available": False,
        "production_write_authorized": False,
    }
    item["review_candidate_sha256"] = canonical_sha256(item)
    return item


class CiscoC09AcceptanceDecisionTests(unittest.TestCase):
    def test_accept_completes_virtual_lab_gate_only(self):
        result = bind_c09_repository_decision(
            candidate(),
            decision_id="C09-DEC-001",
            authority_ref="authority:lab-review",
            authority_attestation_sha256="4" * 64,
            decision="accept",
        )
        self.assertTrue(result["repository_live_evidence_accepted"])
        self.assertTrue(result["c09_complete"])
        self.assertFalse(result["physical_hardware_claimed"])
        self.assertFalse(result["production_writer_available"])
        self.assertFalse(result["production_write_authorized"])

    def test_reject_and_self_promoted_candidate_fail_safe(self):
        result = bind_c09_repository_decision(
            candidate(),
            decision_id="C09-DEC-002",
            authority_ref="authority:lab-review",
            authority_attestation_sha256="5" * 64,
            decision="reject",
        )
        self.assertFalse(result["c09_complete"])

        item = candidate()
        item["physical_hardware_claimed"] = True
        item["review_candidate_sha256"] = canonical_sha256({k: v for k, v in item.items() if k != "review_candidate_sha256"})
        with self.assertRaisesRegex(CiscoC09AcceptanceDecisionError, "crossed acceptance boundary"):
            bind_c09_repository_decision(
                item,
                decision_id="C09-DEC-003",
                authority_ref="authority:lab-review",
                authority_attestation_sha256="6" * 64,
                decision="accept",
            )


if __name__ == "__main__":
    unittest.main()
