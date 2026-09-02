import unittest

from router_configuration.deployment_profile import DeploymentProfileValidator


class DeploymentProfileTests(unittest.TestCase):
    def base(self):
        return {
            "schema_version": "1.0",
            "site_name": "rd",
            "environment": "production",
            "operator_mode": "guided",
            "allow_write": False,
            "device": {
                "id": "rd-router-01",
                "vendor": "mikrotik",
                "management_target": "192.168.11.1",
            },
            "topology": {
                "wans": [
                    {"name": "wan10g", "interface": "sfp-sfpplus1", "capacity_mbps": 10000},
                    {"name": "wan1g", "interface": "ether1", "capacity_mbps": 1000},
                ],
                "core": {"interface": "sfp-sfpplus2", "capacity_mbps": 10000},
            },
            "intent": {
                "vpn": {
                    "wireguard": {"secret_ref": "vault://routers/rd/wg"}
                }
            },
        }

    def test_reference_profile_derives_10_to_1(self):
        result = DeploymentProfileValidator().validate(self.base())
        self.assertTrue(result.ok)
        self.assertEqual(dict(result.wan_weights), {"wan10g": 10, "wan1g": 1})

    def test_plaintext_password_is_rejected(self):
        data = self.base()
        data["device"]["password"] = "bad"
        result = DeploymentProfileValidator().validate(data)
        self.assertFalse(result.ok)
        self.assertTrue(any("plaintext" in error for error in result.errors))

    def test_secret_reference_is_allowed(self):
        self.assertTrue(DeploymentProfileValidator().validate(self.base()).ok)

    def test_duplicate_interface_is_rejected(self):
        data = self.base()
        data["topology"]["core"]["interface"] = "ether1"
        result = DeploymentProfileValidator().validate(data)
        self.assertFalse(result.ok)
        self.assertTrue(any("core interface" in error for error in result.errors))


if __name__ == "__main__":
    unittest.main()
