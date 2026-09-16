import hashlib
import json
import unittest

from router_configuration.vendors.cisco.c06_acceptance_decision import (
    CiscoC06AcceptanceDecisionError,
    bind_c06_repository_decision,
)


def canonical_sha256(value):
    return hashlib.sha256(
        json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
    ).hexdigest()


def candidate():
    item = {
        "schema_version": "cisco-c06-acceptance-review-candidate/1",
        "review_id": "C06-REV-001",
        "reviewer_ref": "reviewer:switch-state",
        "reviewer_attestation_sha256": "1" * 64,
        "target_id": "lab-switch-01",
        "model": "C9300-24T",
        "iosxe_version": "17.18.1",
        "ingest_record_sha256": "2" * 64,
        "state_digest_sha256": "3" * 64,
        "eligible_for_repository_acceptance": True,
        "repository_live_evidence_accepted": False,
        "c06_complete": False,
        "physical_device_verified": False,
        "production_write_authorized": False,
    }
    item["review_candidate_sha256"] = canonical_sha256(item)
    return item


class CiscoC06AcceptanceDecisionTests(unittest.TestCase):
    def test_accept_completes_only_c06_repository_gate(self):
        result = bind_c06_repository_decision(
            candidate(),
            decision_id="C06-DEC-001",
            authority_ref="authority:network-review",
            authority_attestation_sha256="4" * 64,
            decision="accept",
        )
        self.assertTrue(result["repository_live_evidence_accepted"])
        self.assertTrue(result["c06_complete"])
        self.assertFalse(result["physical_device_verified"])
        self.assertFalse(result["production_write_authorized"])

    def test_reject_and_tamper_fail_safe(self):
        result = bind_c06_repository_decision(
            candidate(),
            decision_id="C06-DEC-002",
            authority_ref="authority:network-review",
            authority_attestation_sha256="5" * 64,
            decision="reject",
        )
        self.assertFalse(result["c06_complete"])

        item = candidate()
        item["state_digest_sha256"] = "6" * 64
        with self.assertRaisesRegex(CiscoC06AcceptanceDecisionError, "digest mismatch"):
            bind_c06_repository_decision(
                item,
                decision_id="C06-DEC-003",
                authority_ref="authority:network-review",
                authority_attestation_sha256="7" * 64,
                decision="accept",
            )


if __name__ == "__main__":
    unittest.main()
