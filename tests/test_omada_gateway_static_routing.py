import json
import unittest
from pathlib import Path

class GatewayStaticRoutingTests(unittest.TestCase):
    def test_gateway_route_contract_separates_planes_and_fails_closed(self):
        d=json.loads((Path(__file__).parents[1]/"artifacts"/"OMADA_GATEWAY_STATIC_ROUTING_SCHEMA.json").read_text())
        self.assertEqual(d["task"],"5.04")
        self.assertTrue(d["controller_facts"]["next_hop_and_interface_are_distinct_route_types"])
        self.assertTrue(d["controller_facts"]["switch_static_route_is_separate_device_plane"])
        self.assertTrue(d["safety"]["default_route_or_management_path_change_is_critical"])
        self.assertTrue(d["safety"]["route_overlap_and_more_specific_effect_must_be_analyzed"])
        self.assertEqual(d["safety"]["unknown_support"],"NOT_SUPPORTED_UNVERIFIED")

if __name__=="__main__": unittest.main()
