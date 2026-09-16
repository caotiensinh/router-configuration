import unittest
from copy import deepcopy

from tests.test_cisco_c11_human_review import ingest_record
from router_configuration.vendors.cisco.c11_human_review import build_c11_human_review_candidate
from router_configuration.vendors.cisco.c11_review_decision import (
    CiscoC11ReviewDecisionError,
    bind_c11_review_decision,
)


def review_candidate():
    return build_c11_human_review_candidate(
        ingest_record(),
        review_id="REV-C11-001",
        reviewer_ref="ops:reviewer-01",
        reviewer_attestation_sha256="a" * 64,
    )


class CiscoC11ReviewDecisionTests(unittest.TestCase):
    def test_approve_decision_is_bound_but_non_promoting(self):
        first = bind_c11_review_decision(
            review_candidate(),
            decision_id="DEC-C11-001",
            decision="approve",
            decision_attestation_sha256="b" * 64,
        )
        second = bind_c11_review_decision(
            review_candidate(),
            decision_id="DEC-C11-001",
            decision="approve",
            decision_attestation_sha256="b" * 64,
        )
        self.assertEqual(first, second)
        self.assertEqual(first["decision"], "approve")
        self.assertTrue(first["candidate_human_decision_recorded"])
        self.assertFalse(first["repository_physical_evidence_accepted"])
        self.assertFalse(first["c11_complete"])
        self.assertFalse(first["physical_device_verified"])
        self.assertFalse(first["production_write_authorized"])

    def test_reject_is_supported_without_promoting(self):
        result = bind_c11_review_decision(
            review_candidate(),
            decision_id="DEC-C11-002",
            decision="reject",
            decision_attestation_sha256="c" * 64,
        )
        self.assertEqual(result["decision"], "reject")
        self.assertFalse(result["repository_physical_evidence_accepted"])

    def test_tampered_or_self_promoted_candidate_fails_closed(self):
        candidate = review_candidate()
        candidate["model"] = "C9300-48T"
        with self.assertRaisesRegex(CiscoC11ReviewDecisionError, "digest mismatch"):
            bind_c11_review_decision(
                candidate,
                decision_id="DEC-C11-003",
                decision="approve",
                decision_attestation_sha256="d" * 64,
            )

        candidate = deepcopy(review_candidate())
        candidate["repository_physical_evidence_accepted"] = True
        # Deliberately leave the old digest: tampering must fail before authority can be considered.
        with self.assertRaises(CiscoC11ReviewDecisionError):
            bind_c11_review_decision(
                candidate,
                decision_id="DEC-C11-004",
                decision="approve",
                decision_attestation_sha256="e" * 64,
            )

    def test_invalid_decision_or_attestation_fails_closed(self):
        with self.assertRaisesRegex(CiscoC11ReviewDecisionError, "unsupported"):
            bind_c11_review_decision(
                review_candidate(),
                decision_id="DEC-C11-005",
                decision="maybe",
                decision_attestation_sha256="f" * 64,
            )
        with self.assertRaisesRegex(CiscoC11ReviewDecisionError, "decision_attestation"):
            bind_c11_review_decision(
                review_candidate(),
                decision_id="DEC-C11-006",
                decision="approve",
                decision_attestation_sha256="bad",
            )


if __name__ == "__main__":
    unittest.main()
