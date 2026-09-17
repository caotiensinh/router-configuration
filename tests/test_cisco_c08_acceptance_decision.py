import hashlib
import json
import unittest

from router_configuration.vendors.cisco.c08_acceptance_decision import (
    CiscoC08AcceptanceDecisionError,
    bind_c08_repository_decision,
)


def canonical_sha256(value):
    return hashlib.sha256(
        json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
    ).hexdigest()


def candidate():
    item = {
        "schema_version": "cisco-c08-human-approval-review-candidate/1",
        "approval_record_id": "APR-001",
        "approver_ref": "human:operator",
        "approver_attestation_sha256": "1" * 64,
        "change_id": "CHG-001",
        "target_id": "lab-router-01",
        "pre_state_sha256": "2" * 64,
        "approval_sha256": "3" * 64,
        "eligible_for_repository_acceptance": True,
        "human_approved": False,
        "approval_bound": False,
        "c08_complete": False,
        "apply_authorized": False,
        "write_authorized": False,
        "production_write_authorized": False,
    }
    item["review_candidate_sha256"] = canonical_sha256(item)
    return item


class CiscoC08AcceptanceDecisionTests(unittest.TestCase):
    def test_accept_records_human_approval_but_never_write_authority(self):
        result = bind_c08_repository_decision(
            candidate(),
            decision_id="C08-DEC-001",
            authority_ref="authority:change-control",
            authority_attestation_sha256="4" * 64,
            decision="accept",
        )
        self.assertTrue(result["human_approved"])
        self.assertTrue(result["approval_bound"])
        self.assertTrue(result["c08_complete"])
        self.assertFalse(result["apply_authorized"])
        self.assertFalse(result["write_authorized"])
        self.assertFalse(result["production_write_authorized"])

    def test_reject_and_self_promoted_candidate_fail_safe(self):
        result = bind_c08_repository_decision(
            candidate(),
            decision_id="C08-DEC-002",
            authority_ref="authority:change-control",
            authority_attestation_sha256="5" * 64,
            decision="reject",
        )
        self.assertFalse(result["c08_complete"])

        item = candidate()
        item["apply_authorized"] = True
        item["review_candidate_sha256"] = canonical_sha256({k: v for k, v in item.items() if k != "review_candidate_sha256"})
        with self.assertRaisesRegex(CiscoC08AcceptanceDecisionError, "crossed acceptance boundary"):
            bind_c08_repository_decision(
                item,
                decision_id="C08-DEC-003",
                authority_ref="authority:change-control",
                authority_attestation_sha256="6" * 64,
                decision="accept",
            )


if __name__ == "__main__":
    unittest.main()
