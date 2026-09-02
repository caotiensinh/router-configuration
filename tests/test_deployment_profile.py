import copy
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

    def with_explicit_static_routing(self):
        data = copy.deepcopy(self.base())
        data["topology"]["wans"] = [
            {
                "name": "wan10g",
                "interface": "sfp-sfpplus1",
                "capacity_mbps": 10000,
                "addressing": "static",
                "address": "192.0.2.2/30",
                "routing": {
                    "gateway": "192.0.2.1",
                    "table": "to-wan10g",
                    "failover_distance": 1,
                    "health_probe_targets": ["1.1.1.1", "8.8.8.8"],
                },
            },
            {
                "name": "wan1g",
                "interface": "ether1",
                "capacity_mbps": 1000,
                "addressing": "static",
                "address": "198.51.100.2/30",
                "routing": {
                    "gateway": "198.51.100.1",
                    "table": "to-wan1g",
                    "failover_distance": 2,
                    "health_probe_targets": ["9.9.9.9", "208.67.222.222"],
                },
            },
        ]
        data["intent"]["multiwan"] = {
            "mode": "capacity_weighted",
            "failover": True,
            "failback": "health_hysteresis",
        }
        return data

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

    def test_explicit_static_dualwan_routing_facts_are_accepted(self):
        result = DeploymentProfileValidator().validate(self.with_explicit_static_routing())
        self.assertTrue(result.ok, result.errors)
        self.assertEqual(dict(result.wan_weights), {"wan10g": 10, "wan1g": 1})

    def test_partial_routing_facts_are_rejected_instead_of_guessed(self):
        data = self.with_explicit_static_routing()
        del data["topology"]["wans"][0]["routing"]["gateway"]
        data["topology"]["wans"][1]["routing"]["health_probe_targets"] = ["9.9.9.9"]
        result = DeploymentProfileValidator().validate(data)
        self.assertFalse(result.ok)
        rendered = "\n".join(result.errors)
        self.assertIn("routing.gateway is required", rendered)
        self.assertIn("requires at least two independent targets", rendered)

    def test_static_gateway_must_be_on_declared_wan_subnet(self):
        data = self.with_explicit_static_routing()
        data["topology"]["wans"][0]["routing"]["gateway"] = "203.0.113.1"
        result = DeploymentProfileValidator().validate(data)
        self.assertFalse(result.ok)
        self.assertTrue(any("reachable within the static WAN subnet" in error for error in result.errors))

    def test_routing_tables_and_probe_targets_must_be_independent(self):
        data = self.with_explicit_static_routing()
        data["topology"]["wans"][1]["routing"]["table"] = "to-wan10g"
        data["topology"]["wans"][0]["routing"]["health_probe_targets"] = [
            "192.0.2.1",
            "192.0.2.1",
        ]
        result = DeploymentProfileValidator().validate(data)
        self.assertFalse(result.ok)
        rendered = "\n".join(result.errors)
        self.assertIn("duplicate WAN routing table", rendered)
        self.assertIn("must not reuse the WAN gateway", rendered)
        self.assertIn("must be unique", rendered)

    def test_failover_distance_is_required_bounded_and_explicit(self):
        data = self.with_explicit_static_routing()
        del data["topology"]["wans"][0]["routing"]["failover_distance"]
        data["topology"]["wans"][1]["routing"]["failover_distance"] = 0
        result = DeploymentProfileValidator().validate(data)
        self.assertFalse(result.ok)
        rendered = "\n".join(result.errors)
        self.assertIn("failover_distance must be an integer from 1 to 255", rendered)

    def test_failover_distance_must_not_be_inferred_or_duplicated(self):
        data = self.with_explicit_static_routing()
        data["topology"]["wans"][1]["routing"]["failover_distance"] = 1
        result = DeploymentProfileValidator().validate(data)
        self.assertFalse(result.ok)
        self.assertTrue(any("duplicate WAN failover_distance: 1" in error for error in result.errors))


if __name__ == "__main__":
    unittest.main()
