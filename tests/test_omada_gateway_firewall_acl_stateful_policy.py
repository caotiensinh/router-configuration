import json
import unittest
from pathlib import Path

ROOT = Path(__file__).parents[1]

class GatewayFirewallAclStatefulPolicyTests(unittest.TestCase):
    def test_firewall_acl_contract_is_ordered_stateful_and_fail_closed(self):
        data = json.loads((ROOT / "artifacts" / "OMADA_GATEWAY_FIREWALL_ACL_STATEFUL_POLICY_SCHEMA.json").read_text(encoding="utf-8"))
        self.assertEqual(data["task"], "5.08")
        self.assertTrue(data["vendor_facts"]["acl_processing_is_sequential_first_match"])
        self.assertTrue(data["vendor_facts"]["implicit_permit_all_applies_when_no_acl_rule_matches"])
        self.assertTrue(data["security_policy"]["rule_order_must_be_explicit_and_verified"])
        self.assertTrue(data["security_policy"]["acl_plane_must_match_actual_forwarding_path"])
        self.assertEqual(data["safety"]["unknown_capability"], "NOT_SUPPORTED_UNVERIFIED")
        self.assertEqual(data["safety"]["write_acceptance"], "EXECUTED_UNVERIFIED")
        kb = (ROOT / "knowledge" / "OMADA_GATEWAY_FIREWALL_ACL_STATEFUL_POLICY_KB.md").read_text(encoding="utf-8")
        self.assertIn("first matching rule", kb)
        self.assertIn("implicit Permit All", kb)
        self.assertIn("management-survival", kb)

if __name__ == "__main__":
    unittest.main()
