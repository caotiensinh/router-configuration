import json
import unittest
from pathlib import Path

class GatewayDhcpDnsTests(unittest.TestCase):
    def test_dhcp_dns_planes_are_explicit_and_fail_closed(self):
        d=json.loads((Path(__file__).parents[1]/"artifacts"/"OMADA_GATEWAY_DHCP_DNS_SCHEMA.json").read_text())
        self.assertEqual(d["task"],"5.03")
        self.assertTrue(d["dhcp"]["server_and_relay_are_distinct_modes"])
        self.assertTrue(d["dhcp"]["existing_external_server_requires_controller_server_disabled"])
        self.assertTrue(d["dns"]["dns_reachability_must_be_verified_independently_from_dhcp_lease_success"])
        self.assertTrue(d["safety"]["overlapping_or_conflicting_dhcp_servers_forbidden_without_explicit_design"])
        self.assertEqual(d["safety"]["unknown_support"],"NOT_SUPPORTED_UNVERIFIED")

if __name__=="__main__": unittest.main()
