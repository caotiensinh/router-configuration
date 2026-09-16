import json
import unittest
from pathlib import Path

class VpnSecurityBaselineTests(unittest.TestCase):
    def test_vpn_baseline_separates_capability_policy_and_secrets(self):
        d=json.loads((Path(__file__).parents[1]/"artifacts"/"OMADA_VPN_SECURITY_BASELINE_SCHEMA.json").read_text())
        self.assertEqual(d["task"],"10.7")
        self.assertTrue(d["controller_facts"]["server_client_and_site_to_site_are_distinct_workflows"])
        self.assertTrue(d["security_policy"]["vendor_capability_and_project_policy_separate"])
        self.assertTrue(d["security_policy"]["private_keys_psks_passwords_and_tokens_must_not_enter_evidence"])
        self.assertTrue(d["safety"]["successful_tunnel_creation_is_not_pass"])
        self.assertEqual(d["safety"]["unknown_protocol_or_role_support"],"NOT_SUPPORTED_UNVERIFIED")

if __name__=="__main__": unittest.main()
