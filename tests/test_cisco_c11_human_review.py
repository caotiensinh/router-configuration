import hashlib
import json
import unittest

from router_configuration.vendors.cisco.c11_human_review import (
    CiscoC11HumanReviewError,
    build_c11_human_review_candidate,
)


def ingest_record():
    record = {
        "schema_version": "cisco-c11-physical-evidence-ingest/1",
        "source_payload_sha256": "1" * 64,
        "source_run_id": "run-c11-1",
        "target_kind": "physical_switch",
        "model": "C9300-24T",
        "iosxe_version": "17.18.1a",
        "platform_family": "Catalyst 9300",
        "role": "switch",
        "transport": "netconf",
        "claim_contract_digest_sha256": "2" * 64,
        "eligible_for_human_acceptance": True,
        "repository_physical_evidence_accepted": False,
        "c11_complete": False,
        "physical_device_verified": False,
        "production_write_authorized": False,
    }
    record["ingest_record_sha256"] = hashlib.sha256(
        json.dumps(record, sort_keys=True, separators=(",", ":")).encode("utf-8")
    ).hexdigest()
    return record


class CiscoC11HumanReviewTests(unittest.TestCase):
    def test_review_candidate_stays_non_promoting(self):
        result = build_c11_human_review_candidate(
            ingest_record(),
            review_id="REV-C11-001",
            reviewer_ref="ops:reviewer-01",
            reviewer_attestation_sha256="a" * 64,
        )
        self.assertTrue(result["eligible_for_repository_acceptance"])
        self.assertFalse(result["repository_physical_evidence_accepted"])
        self.assertFalse(result["c11_complete"])
        self.assertFalse(result["physical_device_verified"])
        self.assertFalse(result["production_write_authorized"])

    def test_tampered_ingest_record_is_rejected(self):
        record = ingest_record()
        record["model"] = "C9300-48T"
        with self.assertRaisesRegex(CiscoC11HumanReviewError, "digest mismatch"):
            build_c11_human_review_candidate(
                record,
                review_id="REV-C11-001",
                reviewer_ref="ops:reviewer-01",
                reviewer_attestation_sha256="a" * 64,
            )

    def test_ineligible_record_is_rejected_even_if_rehashed(self):
        record = ingest_record()
        record["eligible_for_human_acceptance"] = False
        unsigned = dict(record)
        unsigned.pop("ingest_record_sha256")
        record["ingest_record_sha256"] = hashlib.sha256(
            json.dumps(unsigned, sort_keys=True, separators=(",", ":")).encode("utf-8")
        ).hexdigest()
        with self.assertRaisesRegex(CiscoC11HumanReviewError, "not eligible"):
            build_c11_human_review_candidate(
                record,
                review_id="REV-C11-001",
                reviewer_ref="ops:reviewer-01",
                reviewer_attestation_sha256="a" * 64,
            )


if __name__ == "__main__":
    unittest.main()
