import unittest

from router_configuration.vendors.cisco.c08_human_approval_review import (
    CiscoC08HumanApprovalReviewError,
    build_c08_human_approval_review_candidate,
)
from router_configuration.vendors.cisco.validation_approval import CiscoApprovalBinding


def binding():
    return CiscoApprovalBinding(
        change_id="CHG-C08-001",
        target_id="sw-core-01",
        pre_state_sha256="1" * 64,
        payload_digest_sha256="2" * 64,
        schema_inventory_digest_sha256="3" * 64,
        catalog_digest_sha256="4" * 64,
        validation_sha256="5" * 64,
        model="C9300-24T",
        iosxe_version="17.18.1a",
        documentation_train="17.18",
        platform_family="Catalyst 9300",
        role="switch",
        feature_id="interface.mtu.set",
        target_datastore="candidate",
        approval_sha256="6" * 64,
    )


def evidence():
    return {
        "schema_version": "cisco-c08-human-approval-evidence/1",
        "approval_record_id": "APR-001",
        "approver_ref": "ops:approver-01",
        "approver_attestation_sha256": "7" * 64,
        "change_id": "CHG-C08-001",
        "target_id": "sw-core-01",
        "pre_state_sha256": "1" * 64,
        "approval_sha256": "6" * 64,
        "decision": "approved",
        "production_write_authorized": False,
    }


class CiscoC08HumanApprovalReviewTests(unittest.TestCase):
    def test_candidate_binds_exact_fingerprint_without_promoting(self):
        result = build_c08_human_approval_review_candidate(evidence(), binding=binding())
        self.assertTrue(result["eligible_for_repository_acceptance"])
        self.assertFalse(result["human_approved"])
        self.assertFalse(result["approval_bound"])
        self.assertFalse(result["c08_complete"])
        self.assertFalse(result["apply_authorized"])
        self.assertFalse(result["production_write_authorized"])
        self.assertEqual(len(result["review_candidate_sha256"]), 64)

    def test_wrong_target_or_prestate_is_rejected(self):
        item = evidence()
        item["target_id"] = "sw-core-02"
        with self.assertRaisesRegex(CiscoC08HumanApprovalReviewError, "binding mismatch"):
            build_c08_human_approval_review_candidate(item, binding=binding())
        item = evidence()
        item["pre_state_sha256"] = "9" * 64
        with self.assertRaisesRegex(CiscoC08HumanApprovalReviewError, "pre-state mismatch"):
            build_c08_human_approval_review_candidate(item, binding=binding())

    def test_write_authority_in_evidence_is_rejected(self):
        item = evidence()
        item["production_write_authorized"] = True
        with self.assertRaisesRegex(CiscoC08HumanApprovalReviewError, "cannot authorize"):
            build_c08_human_approval_review_candidate(item, binding=binding())


if __name__ == "__main__":
    unittest.main()
