import json
import unittest
from pathlib import Path

class GatewayVlanSegmentationTests(unittest.TestCase):
    def test_segmentation_contract_is_explicit_and_management_safe(self):
        d=json.loads((Path(__file__).parents[1]/"artifacts"/"OMADA_GATEWAY_VLAN_SEGMENTATION_SCHEMA.json").read_text())
        self.assertEqual(d["task"],"5.02")
        self.assertEqual(d["segmentation"]["interface_purpose"],"L3 VLAN interface / inter-VLAN routing")
        self.assertTrue(d["segmentation"]["port_profile_required_to_activate_wired_membership"])
        self.assertTrue(d["segmentation"]["switch_acl_requires_port_or_vlan_binding"])
        self.assertEqual(d["segmentation"]["implicit_no_match_behavior"],"permit")
        self.assertTrue(d["safety"]["management_vlan_preservation_required"])
        self.assertEqual(d["safety"]["unknown_support"],"NOT_SUPPORTED_UNVERIFIED")

if __name__=="__main__": unittest.main()
