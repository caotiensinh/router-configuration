import unittest

from router_configuration.maintenance_manual import MaintenanceManualError, build_maintenance_manual


BASE = {
    "source_main_sha": "1" * 40,
    "system_id": "omada-network-automation",
    "cadence": "monthly-and-before-risky-change",
    "pre_maintenance_checks": ["Confirm approved maintenance window and current health."],
    "backup_checks": ["Verify current backup exists and restore prerequisites are known."],
    "firmware_lifecycle_checks": ["Check exact model/HW/region/controller compatibility before firmware change."],
    "routine_tasks": ["Review logs, alerts, storage and knowledge-package freshness."],
    "post_maintenance_verification": ["Run fresh read-back and intended/negative-control checks."],
    "rollback_readiness_checks": ["Confirm rollback artifact and recovery path remain available."],
    "escalation_steps": ["Escalate unresolved drift with sanitized evidence."],
    "evidence_refs": ["evidence://main/verified"],
    "known_restrictions": ["No production mutation is executed by this manual builder."],
}


class MaintenanceManualTests(unittest.TestCase):
    def test_builds_deterministic_non_executable_manual(self):
        a = build_maintenance_manual(**BASE).as_dict()
        b = build_maintenance_manual(**BASE).as_dict()
        self.assertEqual(a["manual_sha256"], b["manual_sha256"])
        self.assertTrue(a["instructions_are_non_executable"])
        self.assertFalse(a["production_write_authority"])

    def test_backup_checks_are_mandatory(self):
        with self.assertRaises(MaintenanceManualError):
            build_maintenance_manual(**dict(BASE, backup_checks=[]))

    def test_post_maintenance_verification_is_mandatory(self):
        with self.assertRaises(MaintenanceManualError):
            build_maintenance_manual(**dict(BASE, post_maintenance_verification=[]))

    def test_invalid_main_sha_is_rejected(self):
        with self.assertRaises(MaintenanceManualError):
            build_maintenance_manual(**dict(BASE, source_main_sha="bad"))

    def test_secret_material_is_rejected(self):
        with self.assertRaises(MaintenanceManualError):
            build_maintenance_manual(**dict(BASE, extra={"access_token": "forbidden"}))


if __name__ == "__main__":
    unittest.main()
