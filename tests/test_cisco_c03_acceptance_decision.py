import hashlib
import json
import unittest

from router_configuration.vendors.cisco.c03_acceptance_decision import (
    CiscoC03AcceptanceDecisionError,
    bind_c03_repository_decision,
)


def canonical_sha256(value):
    return hashlib.sha256(
        json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
    ).hexdigest()


def evidence():
    return {
        "schema_version": "cisco-c03-live-evidence/1",
        "source_sha": "1" * 40,
        "stage": "live_readonly_verified",
        "live_target_observed": True,
        "hostkey_verified": True,
        "c03_complete": True,
        "write_operations_performed": False,
        "production_write_authorized": False,
        "physical_device_verified": False,
        "target_host_digest_sha256": "2" * 64,
        "hostname_digest_sha256": "3" * 64,
        "hostkey_pin_digest_sha256": "4" * 64,
        "capability_digest_sha256": "5" * 64,
        "schema_inventory_digest_sha256": "6" * 64,
        "platform_component_digest_sha256": "7" * 64,
        "interface_digest_sha256": "8" * 64,
    }


class CiscoC03AcceptanceDecisionTests(unittest.TestCase):
    def test_accept_binds_exact_sanitized_artifact_without_write_authority(self):
        item = evidence()
        result = bind_c03_repository_decision(
            item,
            artifact_sha256=canonical_sha256(item),
            decision_id="C03-DEC-001",
            authority_ref="reviewer:network-lab",
            authority_attestation_sha256="9" * 64,
            decision="accept",
        )
        self.assertTrue(result["repository_live_evidence_accepted"])
        self.assertTrue(result["repository_c03_complete"])
        self.assertFalse(result["physical_device_verified"])
        self.assertFalse(result["production_write_authorized"])
        self.assertEqual(len(result["decision_record_sha256"]), 64)

    def test_reject_records_decision_without_acceptance(self):
        item = evidence()
        result = bind_c03_repository_decision(
            item,
            artifact_sha256=canonical_sha256(item),
            decision_id="C03-DEC-002",
            authority_ref="reviewer:network-lab",
            authority_attestation_sha256="a" * 64,
            decision="reject",
        )
        self.assertFalse(result["repository_live_evidence_accepted"])
        self.assertFalse(result["repository_c03_complete"])

    def test_tamper_and_unsanitized_metadata_fail_closed(self):
        item = evidence()
        digest = canonical_sha256(item)
        item["interface_digest_sha256"] = "b" * 64
        with self.assertRaisesRegex(CiscoC03AcceptanceDecisionError, "artifact digest mismatch"):
            bind_c03_repository_decision(
                item,
                artifact_sha256=digest,
                decision_id="C03-DEC-003",
                authority_ref="reviewer:network-lab",
                authority_attestation_sha256="c" * 64,
                decision="accept",
            )

        item = evidence()
        item["target_host"] = "198.51.100.10"
        with self.assertRaisesRegex(CiscoC03AcceptanceDecisionError, "forbidden"):
            bind_c03_repository_decision(
                item,
                artifact_sha256=canonical_sha256(item),
                decision_id="C03-DEC-004",
                authority_ref="reviewer:network-lab",
                authority_attestation_sha256="d" * 64,
                decision="accept",
            )


if __name__ == "__main__":
    unittest.main()
