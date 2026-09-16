import json
import unittest
from pathlib import Path

class WlanSecurityBaselineTests(unittest.TestCase):
    def test_wlan_security_is_band_aware_secret_safe_and_fail_closed(self):
        d=json.loads((Path(__file__).parents[1]/"artifacts"/"OMADA_WLAN_SECURITY_BASELINE_SCHEMA.json").read_text())
        self.assertEqual(d["task"],"10.6")
        self.assertTrue(d["band_constraints"]["6ghz_ppsk_unsupported"])
        self.assertTrue(d["band_constraints"]["wpa3_on_6ghz_requires_pmf_mandatory"])
        self.assertTrue(d["security_policy"]["ppsk_keys_and_radius_shared_secrets_must_not_enter_evidence"])
        self.assertTrue(d["safety"]["vendor_capability_and_project_policy_separate"])
        self.assertEqual(d["safety"]["unknown_support"],"NOT_SUPPORTED_UNVERIFIED")

if __name__=="__main__": unittest.main()
