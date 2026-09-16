import json
import unittest
from pathlib import Path

class GatewayNatPortForwardingTests(unittest.TestCase):
    def test_nat_port_forwarding_is_bounded_and_fail_closed(self):
        data=json.loads((Path(__file__).parents[1]/"artifacts"/"OMADA_GATEWAY_NAT_PORT_FORWARDING_SCHEMA.json").read_text())
        self.assertEqual(data["task"],"5.07")
        self.assertTrue(data["vendor_facts"]["source_scope_can_be_limited_to_specific_public_ips"])
        self.assertTrue(data["vendor_facts"]["one_to_one_nat_is_distinct_from_port_forwarding"])
        self.assertTrue(data["security_policy"]["default_source_scope_must_not_be_any_when_a_bounded_source_is_known"])
        self.assertTrue(data["security_policy"]["management_plane_exposure_requires_separate_security_review"])
        self.assertTrue(data["security_policy"]["overlapping_or_conflicting_external_ports_fail_closed"])
        self.assertEqual(data["safety"]["unknown_capability"],"NOT_SUPPORTED_UNVERIFIED")
        self.assertEqual(data["safety"]["write_acceptance"],"EXECUTED_UNVERIFIED")

if __name__=="__main__": unittest.main()
