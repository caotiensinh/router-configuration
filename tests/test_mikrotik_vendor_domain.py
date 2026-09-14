import json
import tempfile
import unittest
from pathlib import Path

from router_configuration.vendors.mikrotik.backup import backup_operations
from router_configuration.vendors.mikrotik.inference import MikroTikReasoningRequest, build_grounded_prompt
from router_configuration.vendors.mikrotik.knowledge import MikroTikOfflineKnowledge
from router_configuration.vendors.mikrotik.postdeploy import BackupArtifact, build_handover_bundle
from router_configuration.vendors.mikrotik.workflow import (
    MikroTikDeploymentStage,
    completion_requirements,
    deployment_contract,
)


class MikroTikVendorDomainTests(unittest.TestCase):
    def test_bundled_knowledge_is_offline_and_searchable(self):
        store = MikroTikOfflineKnowledge.bundled()
        hits = store.search("wireguard allowed-address keepalive")
        self.assertTrue(hits)
        self.assertEqual(hits[0].record.id, "wireguard-peers")

    def test_prompt_redacts_secret_bearing_fields(self):
        prompt, ids = build_grounded_prompt(
            MikroTikReasoningRequest(
                task="secure WAN management firewall",
                evidence={"username": "admin", "password": "danger", "nested": {"token": "x"}},
            )
        )
        self.assertIn("<redacted>", prompt)
        self.assertNotIn("danger", prompt)
        self.assertNotIn('"x"', prompt)
        self.assertTrue(ids)

    def test_backup_contract_requires_two_distinct_artifact_types(self):
        ops = backup_operations(phase="post_change")
        self.assertEqual({item.kind.value for item in ops}, {"sanitized_export", "binary_system_backup"})
        binary = next(item for item in ops if item.kind.value == "binary_system_backup")
        self.assertTrue(binary.sensitive)
        self.assertTrue(binary.requires_secret_reference)

    def test_workflow_cannot_complete_without_handover_stage(self):
        stages = [item.stage for item in deployment_contract()]
        self.assertLess(stages.index(MikroTikDeploymentStage.VERIFY), stages.index(MikroTikDeploymentStage.POST_CHANGE_BACKUP))
        self.assertLess(stages.index(MikroTikDeploymentStage.POST_CHANGE_BACKUP), stages.index(MikroTikDeploymentStage.GENERATE_HANDOVER))
        self.assertLess(stages.index(MikroTikDeploymentStage.GENERATE_HANDOVER), stages.index(MikroTikDeploymentStage.COMPLETE))
        self.assertIn("operations and maintenance guide generated", completion_requirements())

    def test_handover_bundle_hashes_backup_and_generates_documents(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            backup = root / "router.backup"
            backup.write_bytes(b"binary-placeholder")
            record = {
                "status": "completed",
                "deployment_id": "dep-1",
                "site": "lab",
                "device": {"identity": "r1", "model": "CHR", "routeros_version": "7.24.1"},
                "intent": {"kind": "secure_internet_gateway"},
                "changes": ["firewall baseline"],
                "verification": [{"name": "management_path_survives", "status": "pass"}],
                "pre_state_sha256": "a",
                "post_state_sha256": "b",
            }
            result = build_handover_bundle(
                output_dir=root / "handover",
                deployment_record=record,
                backup_artifacts=[BackupArtifact("binary", backup, True, "7.24.1")],
            )
            names = {path.name for path in result.files}
            self.assertIn("00_deployment_completion.md", names)
            self.assertIn("03_operations_maintenance.md", names)
            self.assertIn("99_bundle_manifest.json", names)
            manifest = json.loads((root / "handover" / "05_backup_manifest.json").read_text())
            self.assertTrue(manifest["artifacts"][0]["contains_sensitive_data"])


if __name__ == "__main__":
    unittest.main()
