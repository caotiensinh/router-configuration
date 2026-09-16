import json
import unittest
from pathlib import Path

class GatewayPolicyRoutingTests(unittest.TestCase):
    def test_policy_routing_contract_is_distinct_and_fail_closed(self):
        d=json.loads((Path(__file__).parents[1]/"artifacts"/"OMADA_GATEWAY_POLICY_ROUTING_SCHEMA.json").read_text())
        self.assertEqual(d["task"],"5.05")
        self.assertTrue(d["controller_facts"]["policy_routing_selects_wan_from_source_destination_protocol"])
        self.assertTrue(d["controller_facts"]["fallback_to_other_wan_is_explicit_per_rule"])
        self.assertTrue(d["controller_facts"]["policy_routing_and_static_route_are_distinct_objects"])
        self.assertTrue(d["safety"]["precedence_must_not_be_invented_without_exact_controller_evidence"])
        self.assertEqual(d["safety"]["unknown_support"],"NOT_SUPPORTED_UNVERIFIED")

if __name__=="__main__": unittest.main()
