import json
import unittest
from pathlib import Path

class GatewayInterfacesWanLanTests(unittest.TestCase):
    def test_contract_separates_wan_lan_and_fails_closed(self):
        d=json.loads((Path(__file__).parents[1]/"artifacts"/"OMADA_GATEWAY_INTERFACES_WAN_LAN_SCHEMA.json").read_text())
        self.assertEqual(d["task"],"5.01")
        self.assertEqual(d["safety"]["unknown_support"],"NOT_SUPPORTED_UNVERIFIED")
        self.assertTrue(d["wan"]["wan_settings_override_can_break_internet_after_adoption"])
        self.assertTrue(d["wan"]["wan_port_count_mismatch_can_reboot_after_adoption"])
        self.assertEqual(set(d["lan"]["network_purposes"]),{"interface","vlan"})
        self.assertTrue(d["lan"]["default_network_not_deletable"])

if __name__=="__main__": unittest.main()
