import hashlib
import json
import unittest

from router_configuration.vendors.cisco.c12_final_handover_decision import (
    CiscoC12FinalHandoverDecisionError,
    bind_c12_final_handover_decision,
)


def canonical_sha256(value):
    return hashlib.sha256(
        json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
    ).hexdigest()


def manifest():
    item = {
        "schema_version": "cisco-c12-handover-manifest/1",
        "handover_id": "HO-C12-001",
        "owner_ref": "ops:owner-01",
        "stage_evidence_sha256": {
            "c06": "1" * 64,
            "c07": "2" * 64,
            "c08": "3" * 64,
            "c09": "4" * 64,
            "c10": "5" * 64,
            "c11": "6" * 64,
        },
        "ready_for_c12_human_review": True,
        "c12_complete": False,
        "production_writer_available": False,
        "production_write_authorized": False,
    }
    item["manifest_sha256"] = canonical_sha256(item)
    return item


def production_evidence(manifest_sha):
    item = {
        "schema_version": "cisco-c12-production-deployment-evidence/1",
        "deployment_id": "DEPLOY-C12-001",
        "change_id": "CHANGE-C12-001",
        "source_sha": "7" * 40,
        "production_authority_ref": "authority:production-change-board",
        "handover_manifest_sha256": manifest_sha,
        "plan_sha256": "8" * 64,
        "changeset_sha256": "9" * 64,
        "production_authorization_attestation_sha256": "a" * 64,
        "prechange_backup_sha256": "b" * 64,
        "postchange_backup_sha256": "c" * 64,
        "pre_state_sha256": "d" * 64,
        "post_state_sha256": "e" * 64,
        "execution_evidence_sha256": "f" * 64,
        "verification_evidence_sha256": "0" * 64,
        "live_production_execution_observed": True,
        "production_authorization_validated": True,
        "apply_succeeded": True,
        "readback_verified": True,
        "desired_state_verified": True,
        "security_behavior_verified": True,
        "postchange_backup_verified": True,
        "rollback_available": True,
        "physical_device_verified": True,
        "verified_production_deployment": True,
        "eligible_for_final_handover": True,
        "production_writer_available": False,
        "production_write_authorized": False,
        "observation_sha256": "1" * 64,
    }
    item["verification_record_sha256"] = canonical_sha256(item)
    return item


class CiscoC12FinalHandoverDecisionTests(unittest.TestCase):
    def test_accept_completes_only_final_handover_without_future_write_authority(self):
        handover = manifest()
        evidence = production_evidence(handover["manifest_sha256"])
        result = bind_c12_final_handover_decision(
            handover,
            evidence,
            decision_id="C12-HANDOVER-DECISION-001",
            authority_ref="authority:handover-board",
            authority_attestation_sha256="2" * 64,
            decision="accept",
        )
        self.assertTrue(result["verified_production_deployment"])
        self.assertTrue(result["final_handover_accepted"])
        self.assertTrue(result["c12_complete"])
        self.assertTrue(result["physical_device_verified"])
        self.assertFalse(result["production_writer_available"])
        self.assertFalse(result["production_write_authorized"])
        self.assertEqual(len(result["decision_record_sha256"]), 64)

    def test_reject_preserves_verified_deployment_but_does_not_complete_handover(self):
        handover = manifest()
        evidence = production_evidence(handover["manifest_sha256"])
        result = bind_c12_final_handover_decision(
            handover,
            evidence,
            decision_id="C12-HANDOVER-DECISION-002",
            authority_ref="authority:handover-board",
            authority_attestation_sha256="2" * 64,
            decision="reject",
        )
        self.assertTrue(result["verified_production_deployment"])
        self.assertFalse(result["final_handover_accepted"])
        self.assertFalse(result["c12_complete"])
        self.assertFalse(result["production_write_authorized"])

    def test_mismatched_manifest_binding_fails_closed(self):
        handover = manifest()
        evidence = production_evidence("9" * 64)
        with self.assertRaisesRegex(CiscoC12FinalHandoverDecisionError, "not bound to this handover manifest"):
            bind_c12_final_handover_decision(
                handover,
                evidence,
                decision_id="C12-HANDOVER-DECISION-003",
                authority_ref="authority:handover-board",
                authority_attestation_sha256="2" * 64,
                decision="accept",
            )

    def test_tampered_manifest_or_evidence_fails_closed(self):
        handover = manifest()
        handover["owner_ref"] = "ops:tampered"
        evidence = production_evidence("8" * 64)
        with self.assertRaisesRegex(CiscoC12FinalHandoverDecisionError, "manifest digest mismatch"):
            bind_c12_final_handover_decision(
                handover,
                evidence,
                decision_id="C12-HANDOVER-DECISION-004",
                authority_ref="authority:handover-board",
                authority_attestation_sha256="2" * 64,
                decision="accept",
            )

    def test_invalid_decision_fails_closed(self):
        handover = manifest()
        evidence = production_evidence(handover["manifest_sha256"])
        with self.assertRaisesRegex(CiscoC12FinalHandoverDecisionError, "unsupported final handover decision"):
            bind_c12_final_handover_decision(
                handover,
                evidence,
                decision_id="C12-HANDOVER-DECISION-005",
                authority_ref="authority:handover-board",
                authority_attestation_sha256="2" * 64,
                decision="approve",
            )


if __name__ == "__main__":
    unittest.main()
