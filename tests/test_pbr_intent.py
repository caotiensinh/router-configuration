import unittest

from router_configuration.pbr_intent import PbrIntentError, normalize_pbr_intent


class PbrIntentTests(unittest.TestCase):
    def test_normalization_uses_routing_rules_without_mangle_marks(self):
        result = normalize_pbr_intent(
            {
                "enabled": True,
                "strategy": "routing_rules",
                "rules": [
                    {
                        "name": "camera-egress",
                        "source_cidr": "192.168.20.0/24",
                        "destination_cidr": "0.0.0.0/0",
                        "in_interface": "vlan20",
                        "table": "to-wan10g",
                        "action": "lookup",
                    }
                ],
            }
        ).attributes
        self.assertEqual(result["strategy"], "routing_rules")
        self.assertFalse(result["mangle_routing_marks"])
        rule = result["rules"][0]
        self.assertTrue(rule["fallback_to_main"])
        self.assertEqual(rule["source_cidr"], "192.168.20.0/24")

    def test_lookup_only_disables_main_fallback_explicitly(self):
        result = normalize_pbr_intent(
            {
                "enabled": True,
                "rules": [
                    {
                        "name": "isolated-egress",
                        "source_cidr": "192.168.30.0/24",
                        "table": "to-wan1g",
                        "action": "lookup_only",
                    }
                ],
            }
        ).attributes
        rule = result["rules"][0]
        self.assertEqual(rule["destination_cidr"], "0.0.0.0/0")
        self.assertFalse(rule["fallback_to_main"])

    def test_source_scope_must_be_bounded(self):
        with self.assertRaisesRegex(PbrIntentError, "bounded IPv4"):
            normalize_pbr_intent(
                {
                    "enabled": True,
                    "rules": [
                        {
                            "name": "unsafe",
                            "source_cidr": "0.0.0.0/0",
                            "table": "to-wan1g",
                        }
                    ],
                }
            )

    def test_main_table_is_rejected(self):
        with self.assertRaisesRegex(PbrIntentError, "non-main"):
            normalize_pbr_intent(
                {
                    "enabled": True,
                    "rules": [
                        {
                            "name": "unsafe",
                            "source_cidr": "192.168.20.0/24",
                            "table": "main",
                        }
                    ],
                }
            )

    def test_mangle_strategy_is_not_silently_accepted(self):
        with self.assertRaisesRegex(PbrIntentError, "strategy=routing_rules"):
            normalize_pbr_intent(
                {
                    "enabled": True,
                    "strategy": "mangle",
                    "rules": [
                        {
                            "name": "rule1",
                            "source_cidr": "192.168.20.0/24",
                            "table": "to-wan1g",
                        }
                    ],
                }
            )

    def test_duplicate_match_and_table_is_rejected(self):
        with self.assertRaisesRegex(PbrIntentError, "duplicate PBR match"):
            normalize_pbr_intent(
                {
                    "enabled": True,
                    "rules": [
                        {
                            "name": "first",
                            "source_cidr": "192.168.20.0/24",
                            "table": "to-wan1g",
                        },
                        {
                            "name": "second",
                            "source_cidr": "192.168.20.0/24",
                            "table": "to-wan1g",
                        },
                    ],
                }
            )

    def test_identifier_injection_is_rejected(self):
        with self.assertRaisesRegex(PbrIntentError, "unsupported characters"):
            normalize_pbr_intent(
                {
                    "enabled": True,
                    "rules": [
                        {
                            "name": "rule;remove",
                            "source_cidr": "192.168.20.0/24",
                            "table": "to-wan1g",
                        }
                    ],
                }
            )


if __name__ == "__main__":
    unittest.main()
