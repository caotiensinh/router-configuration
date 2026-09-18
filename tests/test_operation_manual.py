import unittest

from router_configuration.operation_manual import OperationManualError, build_operation_manual


BASE = {
    "source_main_sha": "1" * 40,
    "system_id": "omada-network-automation",
    "audience": "network-operations",
    "prerequisites": ["Confirm approved maintenance window."],
    "startup_steps": ["Start controller-side read-only health checks."],
    "health_checks": ["Verify controller and managed-device status."],
    "normal_operations": ["Use verified read-only diagnostics before mutation."],
    "shutdown_steps": ["Close the change window after evidence capture."],
    "escalation_steps": ["Escalate unresolved faults with sanitized evidence."],
    "evidence_refs": ["evidence://main/verified"],
    "known_restrictions": ["No hardware-equivalence claim from virtual validation."],
}


class OperationManualTests(unittest.TestCase):
    def test_builds_deterministic_non_executable_manual(self):
        a = build_operation_manual(**BASE).as_dict()
        b = build_operation_manual(**BASE).as_dict()
        self.assertEqual(a["manual_sha256"], b["manual_sha256"])
        self.assertTrue(a["instructions_are_non_executable"])
        self.assertFalse(a["production_write_authority"])

    def test_missing_health_checks_is_rejected(self):
        values = dict(BASE, health_checks=[])
        with self.assertRaises(OperationManualError):
            build_operation_manual(**values)

    def test_missing_evidence_is_rejected(self):
        values = dict(BASE, evidence_refs=[])
        with self.assertRaises(OperationManualError):
            build_operation_manual(**values)

    def test_invalid_main_sha_is_rejected(self):
        values = dict(BASE, source_main_sha="not-a-sha")
        with self.assertRaises(OperationManualError):
            build_operation_manual(**values)

    def test_secret_material_is_rejected(self):
        values = dict(BASE, extra={"password": "forbidden"})
        with self.assertRaises(OperationManualError):
            build_operation_manual(**values)


if __name__ == "__main__":
    unittest.main()
