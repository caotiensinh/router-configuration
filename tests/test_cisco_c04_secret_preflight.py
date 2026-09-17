import json
import unittest

from router_configuration.vendors.cisco.c04_secret_preflight import build_c04_secret_preflight


class CiscoC04SecretPreflightTests(unittest.TestCase):
    def test_missing_platform_binding_is_explicit_without_values(self):
        env = {
            "CISCO_RESTCONF_HOST": "router.example.test",
            "CISCO_RESTCONF_USERNAME": "operator",
            "CISCO_RESTCONF_PASSWORD": "super-secret",
            "CISCO_RESTCONF_PLATFORM_MODEL": "",
            "CISCO_RESTCONF_PLATFORM_TARGET_SHA256": "",
            "CISCO_RESTCONF_PLATFORM_EVIDENCE_SHA256": "",
        }
        result = build_c04_secret_preflight(env, source_sha="1" * 40)
        self.assertFalse(result["ready_for_live_acceptance_probe"])
        self.assertEqual(
            result["missing_required_secret_names"],
            [
                "CISCO_RESTCONF_PLATFORM_MODEL",
                "CISCO_RESTCONF_PLATFORM_TARGET_SHA256",
                "CISCO_RESTCONF_PLATFORM_EVIDENCE_SHA256",
            ],
        )
        rendered = json.dumps(result)
        for value in ("router.example.test", "operator", "super-secret"):
            self.assertNotIn(value, rendered)
        self.assertFalse(result["secret_values_recorded"])

    def test_optional_ca_and_cert_pin_do_not_block_system_trust_path(self):
        env = {
            "CISCO_RESTCONF_HOST": "host",
            "CISCO_RESTCONF_USERNAME": "user",
            "CISCO_RESTCONF_PASSWORD": "password",
            "CISCO_RESTCONF_PLATFORM_MODEL": "C8300-1N1S-4T2X",
            "CISCO_RESTCONF_PLATFORM_TARGET_SHA256": "a" * 64,
            "CISCO_RESTCONF_PLATFORM_EVIDENCE_SHA256": "b" * 64,
            "CISCO_RESTCONF_CA_PEM_B64": "",
            "CISCO_RESTCONF_CERT_SHA256": "",
        }
        result = build_c04_secret_preflight(env, source_sha="2" * 40)
        self.assertTrue(result["ready_for_live_acceptance_probe"])
        self.assertEqual(result["missing_required_secret_names"], [])
        self.assertFalse(result["c04_complete"])
        self.assertFalse(result["production_write_authorized"])


if __name__ == "__main__":
    unittest.main()
