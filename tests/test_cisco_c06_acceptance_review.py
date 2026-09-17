import hashlib
import json
import unittest

from router_configuration.vendors.cisco.c06_acceptance_review import (
    CiscoC06AcceptanceReviewError,
    build_c06_acceptance_review_candidate,
)


def ingest_record():
    record = {
        "schema_version": "cisco-c06-switch-state-evidence-ingest/1",
        "target_id": "sw-core-01",
        "model": "C9300-24T",
        "iosxe_version": "17.18.1a",
        "platform_family": "Catalyst 9300",
        "source_sha": "1" * 40,
        "source_run_id": "run-1",
        "transport": "netconf",
        "state_digest_sha256": "2" * 64,
        "schema_inventory_digest_sha256": "3" * 64,
        "catalog_digest_sha256": "4" * 64,
        "candidate_claims_live_read": True,
        "repository_live_evidence_accepted": False,
        "c06_complete": False,
        "physical_device_verified": False,
        "production_write_authorized": False,
    }
    record["ingest_record_sha256"] = hashlib.sha256(
        json.dumps(record, sort_keys=True, separators=(",", ":")).encode("utf-8")
    ).hexdigest()
    return record


class CiscoC06AcceptanceReviewTests(unittest.TestCase):
    def test_review_candidate_is_deterministic_and_non_promoting(self):
        first = build_c06_acceptance_review_candidate(
            ingest_record(),
            review_id="REV-C06-001",
            reviewer_ref="ops:reviewer-01",
            reviewer_attestation_sha256="a" * 64,
        )
        second = build_c06_acceptance_review_candidate(
            ingest_record(),
            review_id="REV-C06-001",
            reviewer_ref="ops:reviewer-01",
            reviewer_attestation_sha256="a" * 64,
        )
        self.assertEqual(first, second)
        self.assertTrue(first["eligible_for_repository_acceptance"])
        self.assertFalse(first["repository_live_evidence_accepted"])
        self.assertFalse(first["c06_complete"])
        self.assertFalse(first["physical_device_verified"])
        self.assertFalse(first["production_write_authorized"])

    def test_tampered_ingest_digest_is_rejected(self):
        record = ingest_record()
        record["model"] = "C9300-48T"
        with self.assertRaisesRegex(CiscoC06AcceptanceReviewError, "digest mismatch"):
            build_c06_acceptance_review_candidate(
                record,
                review_id="REV-C06-001",
                reviewer_ref="ops:reviewer-01",
                reviewer_attestation_sha256="a" * 64,
            )

    def test_self_promotion_is_rejected_even_with_recomputed_digest(self):
        record = ingest_record()
        record["c06_complete"] = True
        unsigned = dict(record)
        unsigned.pop("ingest_record_sha256")
        record["ingest_record_sha256"] = hashlib.sha256(
            json.dumps(unsigned, sort_keys=True, separators=(",", ":")).encode("utf-8")
        ).hexdigest()
        with self.assertRaisesRegex(CiscoC06AcceptanceReviewError, "acceptance boundary"):
            build_c06_acceptance_review_candidate(
                record,
                review_id="REV-C06-001",
                reviewer_ref="ops:reviewer-01",
                reviewer_attestation_sha256="a" * 64,
            )


if __name__ == "__main__":
    unittest.main()
