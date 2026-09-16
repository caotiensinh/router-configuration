import hashlib
import json
import unittest

from router_configuration.vendors.cisco.c12_production_deployment_evidence import (
    CiscoC12ProductionEvidenceError,
    verify_c12_production_deployment_evidence,
)


def canonical_sha256(value):
    return hashlib.sha256(
        json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
    ).hexdigest()


def observation():
    item = {
        "schema_version": "cisco-c12-production-deployment-observation/1",
        "deployment_id": "DEPLOY-C12-001",
        "change_id": "CHANGE-C12-001",
        "source_sha": "1" * 40,
        "production_authority_ref": "authority:production-change-board",
        "handover_manifest_sha256": "2" * 64,
        "plan_sha256": "3" * 64,
        "changeset_sha256": "4" * 64,
        "production_authorization_attestation_sha256": "5" * 64,
        "prechange_backup_sha256": "6" * 64,
        "postchange_backup_sha256": "7" * 64,
        "pre_state_sha256": "8" * 64,
        "post_state_sha256": "9" * 64,
        "execution_evidence_sha256": "a" * 64,
        "verification_evidence_sha256": "b" * 64,
        "live_production_execution_observed": True,
        "production_authorization_validated": True,
        "apply_succeeded": True,
        "readback_verified": True,
        "desired_state_verified": True,
        "security_behavior_verified": True,
        "postchange_backup_verified": True,
        "rollback_available": True,
        "physical_device_verified": True,
        "reusable_write_authority": False,
    }
    item["observation_sha256"] = canonical_sha256(item)
    return item


class CiscoC12ProductionDeploymentEvidenceTests(unittest.TestCase):
    def test_verified_external_evidence_is_non_authorizing_for_future_writes(self):
        result = verify_c12_production_deployment_evidence(observation())
        self.assertTrue(result["verified_production_deployment"])
        self.assertTrue(result["eligible_for_final_handover"])
        self.assertTrue(result["physical_device_verified"])
        self.assertFalse(result["production_writer_available"])
        self.assertFalse(result["production_write_authorized"])
        self.assertEqual(result["handover_manifest_sha256"], "2" * 64)
        self.assertEqual(len(result["verification_record_sha256"]), 64)

    def test_tampered_observation_fails_closed(self):
        item = observation()
        item["post_state_sha256"] = "c" * 64
        with self.assertRaisesRegex(CiscoC12ProductionEvidenceError, "digest mismatch"):
            verify_c12_production_deployment_evidence(item)

    def test_missing_verification_claim_fails_closed(self):
        item = observation()
        item["readback_verified"] = False
        item["observation_sha256"] = canonical_sha256({k: v for k, v in item.items() if k != "observation_sha256"})
        with self.assertRaisesRegex(CiscoC12ProductionEvidenceError, "readback_verified"):
            verify_c12_production_deployment_evidence(item)

    def test_reusable_write_authority_is_rejected(self):
        item = observation()
        item["reusable_write_authority"] = True
        item["observation_sha256"] = canonical_sha256({k: v for k, v in item.items() if k != "observation_sha256"})
        with self.assertRaisesRegex(CiscoC12ProductionEvidenceError, "reusable write authority"):
            verify_c12_production_deployment_evidence(item)

    def test_physical_verification_is_mandatory(self):
        item = observation()
        item["physical_device_verified"] = False
        item["observation_sha256"] = canonical_sha256({k: v for k, v in item.items() if k != "observation_sha256"})
        with self.assertRaisesRegex(CiscoC12ProductionEvidenceError, "physical verification"):
            verify_c12_production_deployment_evidence(item)


if __name__ == "__main__":
    unittest.main()
