import hashlib
import json
import unittest

from router_configuration.vendors.cisco.c04_acceptance_decision import (
    CiscoC04AcceptanceDecisionError,
    bind_c04_repository_decision,
)


def canonical_sha256(value):
    return hashlib.sha256(
        json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
    ).hexdigest()


def review_record():
    record = {
        "schema_version": "cisco-c04-repository-review/1",
        "source_sha": "1" * 40,
        "source_evidence_digest_sha256": "2" * 64,
        "candidate_live_claim_valid": True,
        "get_only_verified": True,
        "tls_verified": True,
        "redirects_disabled": True,
        "platform_binding_verified": True,
        "repository_evidence_accepted": False,
        "repository_c04_complete": False,
        "production_write_authorized": False,
        "physical_device_verified": False,
    }
    record["review_record_sha256"] = canonical_sha256(record)
    return record


class CiscoC04AcceptanceDecisionTests(unittest.TestCase):
    def test_accept_and_reject_are_bound_to_exact_review_record(self):
        item = review_record()
        accepted = bind_c04_repository_decision(
            item,
            decision_id="C04-DEC-001",
            authority_ref="reviewer:restconf",
            authority_attestation_sha256="3" * 64,
            decision="accept",
        )
        self.assertTrue(accepted["repository_evidence_accepted"])
        self.assertTrue(accepted["repository_c04_complete"])
        self.assertFalse(accepted["production_write_authorized"])

        rejected = bind_c04_repository_decision(
            item,
            decision_id="C04-DEC-002",
            authority_ref="reviewer:restconf",
            authority_attestation_sha256="4" * 64,
            decision="reject",
        )
        self.assertFalse(rejected["repository_evidence_accepted"])
        self.assertFalse(rejected["repository_c04_complete"])

    def test_tamper_or_self_promotion_fails_closed(self):
        item = review_record()
        item["tls_verified"] = False
        with self.assertRaisesRegex(CiscoC04AcceptanceDecisionError, "digest mismatch"):
            bind_c04_repository_decision(
                item,
                decision_id="C04-DEC-003",
                authority_ref="reviewer:restconf",
                authority_attestation_sha256="5" * 64,
                decision="accept",
            )

        item = review_record()
        item["repository_c04_complete"] = True
        item["review_record_sha256"] = canonical_sha256({k: v for k, v in item.items() if k != "review_record_sha256"})
        with self.assertRaisesRegex(CiscoC04AcceptanceDecisionError, "crossed acceptance boundary"):
            bind_c04_repository_decision(
                item,
                decision_id="C04-DEC-004",
                authority_ref="reviewer:restconf",
                authority_attestation_sha256="6" * 64,
                decision="accept",
            )


if __name__ == "__main__":
    unittest.main()
