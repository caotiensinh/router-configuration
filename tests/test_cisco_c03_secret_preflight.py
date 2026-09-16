import json
import unittest

from router_configuration.vendors.cisco.c03_secret_preflight import build_c03_secret_preflight


class CiscoC03SecretPreflightTests(unittest.TestCase):
    def test_missing_names_are_reported_without_values(self):
        env = {
            "CISCO_NETCONF_HOST": "192.0.2.10",
            "CISCO_NETCONF_USERNAME": "operator",
            "CISCO_NETCONF_PASSWORD": "super-secret",
            "CISCO_NETCONF_HOSTKEY_B64": "",
        }
        result = build_c03_secret_preflight(env, source_sha="1" * 40)
        self.assertFalse(result["ready_for_live_probe"])
        self.assertEqual(result["missing_secret_names"], ["CISCO_NETCONF_HOSTKEY_B64"])
        rendered = json.dumps(result)
        for value in ("192.0.2.10", "operator", "super-secret"):
            self.assertNotIn(value, rendered)
        self.assertFalse(result["secret_values_recorded"])
        self.assertFalse(result["c03_complete"])

    def test_all_required_names_present_marks_preflight_ready_only(self):
        env = {
            "CISCO_NETCONF_HOST": "host",
            "CISCO_NETCONF_USERNAME": "user",
            "CISCO_NETCONF_PASSWORD": "password",
            "CISCO_NETCONF_HOSTKEY_B64": "ZmFrZS1ob3N0LWtleS1mb3ItdGVzdGluZy1vbmx5",
        }
        result = build_c03_secret_preflight(env, source_sha="2" * 40)
        self.assertTrue(result["ready_for_live_probe"])
        self.assertEqual(result["missing_secret_names"], [])
        self.assertFalse(result["live_target_observed"])
        self.assertFalse(result["production_write_authorized"])


if __name__ == "__main__":
    unittest.main()
