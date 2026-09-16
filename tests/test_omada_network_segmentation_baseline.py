import json
import unittest
from pathlib import Path

class NetworkSegmentationBaselineTests(unittest.TestCase):
    def test_baseline_is_flow_based_and_fail_closed(self):
        d=json.loads((Path(__file__).parents[1]/"artifacts"/"OMADA_NETWORK_SEGMENTATION_BASELINE_SCHEMA.json").read_text())
        self.assertEqual(d["task"],"10.4")
        self.assertTrue(d["vendor_facts"]["gateway_switch_eap_acl_planes_are_distinct"])
        self.assertTrue(d["safety"]["vendor_capability_and_project_policy_separate"])
        self.assertTrue(d["safety"]["management_and_controller_flows_must_be_allowlisted_before_deny"])
        self.assertTrue(d["safety"]["broad_deny_without_flow_inventory_forbidden"])
        self.assertEqual(d["safety"]["unknown_capability"],"NOT_SUPPORTED_UNVERIFIED")

if __name__=="__main__": unittest.main()
