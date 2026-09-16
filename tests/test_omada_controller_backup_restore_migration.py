import json
import unittest
from pathlib import Path

class ControllerBackupRestoreMigrationTests(unittest.TestCase):
    def test_migration_specializes_parent_and_requires_target_reconciliation(self):
        data=json.loads((Path(__file__).parents[1]/"artifacts"/"OMADA_CONTROLLER_BACKUP_RESTORE_MIGRATION_SCHEMA.json").read_text())
        self.assertEqual(data["task"],"7.12")
        self.assertEqual(data["reuse"]["parent_task"],"4.19")
        self.assertTrue(data["migration"]["site_and_controller_migration_are_distinct"])
        self.assertTrue(data["migration"]["source_and_target_version_compatibility_must_be_prevalidated"])
        self.assertTrue(data["migration"]["forget_source_devices_only_after_target_connected_verification"])
        self.assertEqual(data["safety"]["unknown_compatibility"],"NOT_SUPPORTED_UNVERIFIED")

if __name__=="__main__": unittest.main()
