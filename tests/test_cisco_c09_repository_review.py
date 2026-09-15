import hashlib
import json
import unittest

from router_configuration.vendors.cisco.c09_repository_review import (
    CiscoC09RepositoryReviewError,
    build_c09_repository_review_candidate,
)


def ingest_record():
    record = {
        "schema_version": "cisco-c09-live-evidence-ingest/1",
        "source_payload_sha256": "1" * 64,
        "validated_bundle_sha256": "2" * 64,
        "source_sha": "3" * 40,
        "source_run_id": "run-c09-1",
        "target_id": "c8kv-lab-01",
        "model": "C8000V",
        "iosxe_version": "17.18.1a",
        "candidate_bundle_claims_live_virtual_iosxe": True,
        "candidate_bundle_claims_c09_complete": True,
        "repository_live_evidence_accepted": False,
        "repository_c09_complete": False,
        "physical_hardware_claimed": False,
        "production_writer_available": False,
        "production_write_authorized": False,
    }
    record["ingest_record_sha256"] = hashlib.sha256(
        json.dumps(record, sort_keys=True, separators=(",", ":")).encode("utf-8")
    ).hexdigest()
    return record


class CiscoC09RepositoryReviewTests(unittest.TestCase):
    def test_review_candidate_is_non_promoting(self):
        result = build_c09_repository_review_candidate(
            ingest_record(),
            review_id="REV-C09-001",
            reviewer_ref="lab:reviewer-01",
            reviewer_attestation_sha256="a" * 64,
        )
        self.assertTrue(result["eligible_for_repository_acceptance"])
        self.assertFalse(result["repository_live_evidence_accepted"])
        self.assertFalse(result["c09_complete"])
        self.assertFalse(result["production_write_authorized"])
        self.assertEqual(len(result["review_candidate_sha256"]), 64)

    def test_tampered_record_is_rejected(self):
        record = ingest_record()
        record["source_run_id"] = "tampered"
        with self.assertRaisesRegex(CiscoC09RepositoryReviewError, "digest mismatch"):
            build_c09_repository_review_candidate(
                record,
                review_id="REV-C09-001",
                reviewer_ref="lab:reviewer-01",
                reviewer_attestation_sha256="a" * 64,
            )

    def test_candidate_must_have_semantic_completion_claim(self):
        record = ingest_record()
        record["candidate_bundle_claims_c09_complete"] = False
        unsigned = dict(record)
        unsigned.pop("ingest_record_sha256")
        record["ingest_record_sha256"] = hashlib.sha256(
            json.dumps(unsigned, sort_keys=True, separators=(",", ":")).encode("utf-8")
        ).hexdigest()
        with self.assertRaisesRegex(CiscoC09RepositoryReviewError, "semantic contract"):
            build_c09_repository_review_candidate(
                record,
                review_id="REV-C09-001",
                reviewer_ref="lab:reviewer-01",
                reviewer_attestation_sha256="a" * 64,
            )


if __name__ == "__main__":
    unittest.main()
