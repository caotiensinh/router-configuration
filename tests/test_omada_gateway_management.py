import json
import unittest
from pathlib import Path

class GatewayManagementTests(unittest.TestCase):
    def test_gateway_management_scope_and_safety(self):
        d=json.loads((Path(__file__).parents[1]/"artifacts"/"OMADA_GATEWAY_MANAGEMENT_SCHEMA.json").read_text())
        self.assertEqual(d["task"],"7.07")
        self.assertTrue(d["controller_facts"]["one_router_per_site_documented"])
        self.assertTrue(d["controller_facts"]["available_functions_vary_by_model_and_device_status"])
        self.assertEqual(d["safety"]["unknown_feature_support"],"NOT_SUPPORTED_UNVERIFIED")
        self.assertTrue(d["ownership"]["controller_managed_state_must_not_be_confused_with_standalone_state"])

if __name__=="__main__": unittest.main()
