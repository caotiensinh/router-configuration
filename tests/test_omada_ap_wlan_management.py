import json
import unittest
from pathlib import Path

class ApWlanManagementTests(unittest.TestCase):
    def test_ap_wlan_management_separates_effective_planes(self):
        d=json.loads((Path(__file__).parents[1]/"artifacts"/"OMADA_AP_WLAN_MANAGEMENT_SCHEMA.json").read_text())
        self.assertEqual(d["task"],"7.09")
        self.assertTrue(d["controller_facts"]["per_ap_ssid_override_is_distinct_from_site_wlan_group"])
        self.assertTrue(d["controller_facts"]["radio_parameters_are_band_specific"])
        self.assertTrue(d["controller_facts"]["mesh_requires_supported_models_and_same_site"])
        self.assertTrue(d["safety"]["ssid_or_security_change_requires_client_impact_analysis"])
        self.assertEqual(d["safety"]["unknown_support"],"NOT_SUPPORTED_UNVERIFIED")

if __name__=="__main__": unittest.main()
