import hashlib
import json
import unittest

from router_configuration.vendors.cisco.restconf_evidence_promotion import (
    CiscoRestconfPromotionError,
    verify_c04_live_evidence,
)


def canonical_sha256(value):
    raw = json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True)
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()


def successful_evidence():
    item = {
        "schema_version": "cisco-c04-live-restconf-evidence/2",
        "source_sha": "1" * 40,
        "knowledge_digest_sha256": "2" * 64,
        "stage": "live_readonly_probe",
        "live_target_observed": True,
        "c04_complete": True,
        "request_method_scope": ["GET"],
        "tls_certificate_verification_required": True,
        "redirect_following_allowed": False,
        "credentials_persisted": False,
        "platform_evidence_bound": True,
        "production_write_authorized": False,
        "physical_device_verified": False,
        "write_operations_performed": False,
        "result": "live_readonly_admitted",
        "target_host_digest_sha256": "3" * 64,
        "target_port": 443,
        "restconf_root_digest_sha256": "4" * 64,
        "capability_inventory_digest_sha256": "5" * 64,
        "capability_count": 4,
        "fields_capability_observed": True,
        "identity_digest_sha256": "6" * 64,
        "hostname_digest_sha256": "7" * 64,
        "iosxe_version": "17.18.1a",
        "documentation_train": "17.18",
        "peer_certificate_sha256": "8" * 64,
        "platform_admission_status": "READ_ONLY_ADMITTED",
        "platform_family": "Catalyst 8000V",
        "admitted_model": "C8000V",
        "platform_evidence_digest_sha256": "9" * 64,
    }
    item["evidence_digest_sha256"] = canonical_sha256(item)
    return item


class CiscoRestconfPromotionTests(unittest.TestCase):
    def test_successful_evidence_builds_non_promoted_review_record(self):
        record = verify_c04_live_evidence(successful_evidence())
        self.assertTrue(record["candidate_live_claim_valid"])
        self.assertTrue(record["get_only_verified"])
        self.assertTrue(record["tls_verified"])
        self.assertFalse(record["repository_evidence_accepted"])
        self.assertFalse(record["repository_c04_complete"])
        self.assertEqual(len(record["review_record_sha256"]), 64)

    def test_tampered_digest_is_rejected(self):
        item = successful_evidence()
        item["iosxe_version"] = "26.1.1"
        with self.assertRaisesRegex(CiscoRestconfPromotionError, "digest mismatch"):
            verify_c04_live_evidence(item)

    def test_redirect_or_write_boundary_violation_is_rejected(self):
        for field, value in (("redirect_following_allowed", True), ("write_operations_performed", True)):
            with self.subTest(field=field):
                item = successful_evidence()
                item[field] = value
                item["evidence_digest_sha256"] = canonical_sha256({k: v for k, v in item.items() if k != "evidence_digest_sha256"})
                with self.assertRaises(CiscoRestconfPromotionError):
                    verify_c04_live_evidence(item)

    def test_missing_platform_binding_or_digest_is_rejected(self):
        item = successful_evidence()
        item["platform_evidence_bound"] = False
        item["evidence_digest_sha256"] = canonical_sha256({k: v for k, v in item.items() if k != "evidence_digest_sha256"})
        with self.assertRaisesRegex(CiscoRestconfPromotionError, "platform evidence"):
            verify_c04_live_evidence(item)

        item = successful_evidence()
        item["peer_certificate_sha256"] = "bad"
        item["evidence_digest_sha256"] = canonical_sha256({k: v for k, v in item.items() if k != "evidence_digest_sha256"})
        with self.assertRaisesRegex(CiscoRestconfPromotionError, "peer_certificate"):
            verify_c04_live_evidence(item)


if __name__ == "__main__":
    unittest.main()
