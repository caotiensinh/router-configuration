import json
import unittest
from pathlib import Path


class OmadaControllerTroubleshooting715Tests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.data = json.loads(
            (Path(__file__).parents[1] / "artifacts" / "OMADA_CONTROLLER_TROUBLESHOOTING_SCHEMA.json").read_text()
        )

    def test_evidence_precedes_mutation(self):
        d = self.data
        self.assertEqual(d["task"], "7.15")
        self.assertEqual(d["diagnostic_order"][0], "capture_identity_and_current_state")
        self.assertEqual(d["diagnostic_order"][1], "collect_read_only_reachability_status_logs_events_alerts_and_network_tools")
        self.assertTrue(d["safety"]["read_only_evidence_precedes_mutation"])
        self.assertFalse(d["safety"]["write_transport_present"])

    def test_destructive_generic_fixes_are_rejected(self):
        safety = self.data["safety"]
        self.assertTrue(safety["factory_reset_is_not_first_line"])
        self.assertTrue(safety["firmware_upgrade_is_not_first_line"])
        self.assertTrue(safety["force_provision_is_not_first_line"])
        self.assertTrue(safety["forget_device_is_not_first_line"])
        self.assertTrue(safety["broad_firewall_disable_is_forbidden_as_generic_fix"])

    def test_unresolved_root_cause_is_an_explicit_valid_outcome(self):
        self.assertIn("ROOT_CAUSE_UNRESOLVED", self.data["outcomes"])
        self.assertTrue(self.data["safety"]["root_cause_may_remain_unresolved"])
        self.assertEqual(self.data["safety"]["unknown_tool_support"], "NOT_SUPPORTED_UNVERIFIED")
        self.assertFalse(self.data["safety"]["credentials_or_secrets_in_evidence"])


if __name__ == "__main__":
    unittest.main()
