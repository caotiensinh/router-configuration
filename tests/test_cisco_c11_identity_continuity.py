import hashlib
import json
import unittest

from router_configuration.vendors.cisco.c11_identity_continuity import (
    CiscoC11IdentityContinuityError,
    verify_c11_identity_continuity,
)


def canonical_sha256(value):
    return hashlib.sha256(
        json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
    ).hexdigest()


def review_candidate():
    item = {
        "schema_version": "cisco-c11-human-review-candidate/1",
        "review_id": "C11-REV-001",
        "reviewer_ref": "reviewer:physical-lab",
        "reviewer_attestation_sha256": "1" * 64,
        "target_kind": "physical_router",
        "model": "C8300-1N1S-4T2X",
        "iosxe_version": "17.18.1a",
        "platform_family": "Catalyst 8300",
        "ingest_record_sha256": "2" * 64,
        "claim_contract_digest_sha256": "3" * 64,
        "eligible_for_repository_acceptance": True,
        "repository_physical_evidence_accepted": False,
        "c11_complete": False,
        "physical_device_verified": False,
        "production_write_authorized": False,
    }
    item["review_candidate_sha256"] = canonical_sha256(item)
    return item


def decision_record(review):
    item = {
        "schema_version": "cisco-c11-review-decision-candidate/1",
        "decision_id": "C11-DEC-001",
        "decision": "approve",
        "decision_attestation_sha256": "4" * 64,
        "review_candidate_sha256": review["review_candidate_sha256"],
        "ingest_record_sha256": review["ingest_record_sha256"],
        "claim_contract_digest_sha256": review["claim_contract_digest_sha256"],
        "target_kind": review["target_kind"],
        "model": review["model"],
        "iosxe_version": review["iosxe_version"],
        "platform_family": review["platform_family"],
        "candidate_human_decision_recorded": True,
        "repository_physical_evidence_accepted": False,
        "c11_complete": False,
        "physical_device_verified": False,
        "production_write_authorized": False,
    }
    item["decision_record_sha256"] = canonical_sha256(item)
    return item


def identity_observation(review):
    item = {
        "schema_version": "cisco-c11-identity-observation/1",
        "target_kind": review["target_kind"],
        "model": review["model"],
        "iosxe_version": review["iosxe_version"],
        "platform_family": review["platform_family"],
        "target_identity_digest_sha256": "5" * 64,
        "identity_attestation_sha256": "6" * 64,
        "physical_presence_attested": True,
        "virtualization": False,
        "production_write_authorized": False,
    }
    item["identity_observation_sha256"] = canonical_sha256(item)
    return item


class CiscoC11IdentityContinuityTests(unittest.TestCase):
    def test_identity_continuity_is_review_ready_but_non_promoting(self):
        review = review_candidate()
        result = verify_c11_identity_continuity(review, decision_record(review), identity_observation(review))
        self.assertTrue(result["identity_continuity_verified"])
        self.assertTrue(result["eligible_for_physical_acceptance"])
        self.assertFalse(result["repository_physical_evidence_accepted"])
        self.assertFalse(result["physical_device_verified"])
        self.assertFalse(result["c11_complete"])
        self.assertFalse(result["production_write_authorized"])

    def test_reject_decision_or_identity_mismatch_fails_closed(self):
        review = review_candidate()
        decision = decision_record(review)
        decision["decision"] = "reject"
        decision["decision_record_sha256"] = canonical_sha256({k: v for k, v in decision.items() if k != "decision_record_sha256"})
        with self.assertRaisesRegex(CiscoC11IdentityContinuityError, "approve decision"):
            verify_c11_identity_continuity(review, decision, identity_observation(review))

        decision = decision_record(review)
        observation = identity_observation(review)
        observation["model"] = "C8500-12X"
        observation["identity_observation_sha256"] = canonical_sha256({k: v for k, v in observation.items() if k != "identity_observation_sha256"})
        with self.assertRaisesRegex(CiscoC11IdentityContinuityError, "mismatch: model"):
            verify_c11_identity_continuity(review, decision, observation)


if __name__ == "__main__":
    unittest.main()
