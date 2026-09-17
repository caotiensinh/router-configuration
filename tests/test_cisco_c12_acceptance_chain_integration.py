import hashlib
import json
import unittest

from router_configuration.vendors.cisco.c12_final_handover_decision import bind_c12_final_handover_decision
from router_configuration.vendors.cisco.c12_handover_manifest import build_c12_handover_manifest
from router_configuration.vendors.cisco.c12_production_deployment_evidence import verify_c12_production_deployment_evidence


def canonical_sha256(value):
    return hashlib.sha256(
        json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
    ).hexdigest()


class CiscoC12AcceptanceChainIntegrationTests(unittest.TestCase):
    def test_manifest_to_verified_deployment_to_final_handover_chain(self):
        stages = {}
        for index, stage in enumerate(("c06", "c07", "c08", "c09", "c10", "c11"), start=1):
            stages[stage] = {
                "complete": True,
                "evidence_sha256": f"{index:x}" * 64,
                "production_write_authorized": False,
            }
        stages["c11"]["physical_device_verified"] = True

        manifest = build_c12_handover_manifest(
            stages,
            handover_id="HO-C12-INTEGRATION-001",
            owner_ref="ops:owner-01",
        )

        observation = {
            "schema_version": "cisco-c12-production-deployment-observation/1",
            "deployment_id": "DEPLOY-C12-INTEGRATION-001",
            "change_id": "CHANGE-C12-INTEGRATION-001",
            "source_sha": "7" * 40,
            "production_authority_ref": "authority:production-change-board",
            "handover_manifest_sha256": manifest["manifest_sha256"],
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
            "reusable_write_authority": False,
        }
        observation["observation_sha256"] = canonical_sha256(observation)

        deployment = verify_c12_production_deployment_evidence(observation)
        final = bind_c12_final_handover_decision(
            manifest,
            deployment,
            decision_id="C12-HANDOVER-INTEGRATION-001",
            authority_ref="authority:handover-board",
            authority_attestation_sha256="2" * 64,
            decision="accept",
        )

        self.assertTrue(deployment["verified_production_deployment"])
        self.assertTrue(final["c12_complete"])
        self.assertTrue(final["final_handover_accepted"])
        self.assertFalse(final["production_writer_available"])
        self.assertFalse(final["production_write_authorized"])


if __name__ == "__main__":
    unittest.main()
