import unittest

from router_configuration.qos_intent import QoSIntentError, normalize_qos_intent


class QoSIntentTests(unittest.TestCase):
    def test_legacy_policy_remains_deferred_without_invented_runtime_facts(self):
        result = normalize_qos_intent(
            {"enabled": True, "policy": "latency_sensitive_first"}
        )
        self.assertEqual(
            result.attributes,
            {"enabled": True, "policy": "latency_sensitive_first"},
        )
        self.assertNotIn("egress_limits_mbps", result.attributes)
        self.assertNotIn("classes", result.attributes)

    def test_explicit_policy_is_normalized_deterministically(self):
        result = normalize_qos_intent(
            {
                "enabled": True,
                "policy": "latency_sensitive_first",
                "egress_limits_mbps": {"wan10g": 9500, "wan1g": 950},
                "classes": [
                    {
                        "name": "default",
                        "priority": 8,
                        "bandwidth_percent": 50,
                        "default": True,
                        "dscp": [],
                    },
                    {
                        "name": "voice",
                        "priority": 1,
                        "bandwidth_percent": 20,
                        "dscp": [46],
                    },
                    {
                        "name": "video",
                        "priority": 3,
                        "bandwidth_percent": 30,
                        "dscp": [34, 36],
                    },
                ],
            }
        )
        self.assertEqual(result.attributes["classification"], "existing_dscp_only")
        self.assertEqual(result.attributes["queue_kind"], "fq-codel")
        self.assertEqual(
            result.attributes["egress_limits_mbps"],
            {"wan10g": 9500, "wan1g": 950},
        )
        self.assertEqual(
            [item["name"] for item in result.attributes["classes"]],
            ["voice", "video", "default"],
        )

    def test_partial_explicit_facts_fail_closed(self):
        with self.assertRaisesRegex(QoSIntentError, "incomplete"):
            normalize_qos_intent(
                {
                    "enabled": True,
                    "policy": "latency_sensitive_first",
                    "egress_limits_mbps": {"wan1": 100},
                }
            )

    def test_dscp_overlap_is_rejected(self):
        with self.assertRaisesRegex(QoSIntentError, "DSCP 46"):
            normalize_qos_intent(
                {
                    "enabled": True,
                    "egress_limits_mbps": {"wan1": 100},
                    "classes": [
                        {"name": "voice", "priority": 1, "bandwidth_percent": 20, "dscp": [46]},
                        {"name": "video", "priority": 2, "bandwidth_percent": 20, "dscp": [46]},
                        {"name": "default", "priority": 8, "bandwidth_percent": 60, "default": True, "dscp": []},
                    ],
                }
            )

    def test_exactly_one_default_class_is_required(self):
        with self.assertRaisesRegex(QoSIntentError, "exactly one default"):
            normalize_qos_intent(
                {
                    "enabled": True,
                    "egress_limits_mbps": {"wan1": 100},
                    "classes": [
                        {"name": "voice", "priority": 1, "bandwidth_percent": 50, "dscp": [46]},
                        {"name": "bulk", "priority": 8, "bandwidth_percent": 50, "dscp": [0]},
                    ],
                }
            )

    def test_bandwidth_percent_must_not_exceed_parent_budget(self):
        with self.assertRaisesRegex(QoSIntentError, "must not exceed 100"):
            normalize_qos_intent(
                {
                    "enabled": True,
                    "egress_limits_mbps": {"wan1": 100},
                    "classes": [
                        {"name": "voice", "priority": 1, "bandwidth_percent": 60, "dscp": [46]},
                        {"name": "default", "priority": 8, "bandwidth_percent": 50, "default": True, "dscp": []},
                    ],
                }
            )

    def test_default_class_cannot_claim_dscp(self):
        with self.assertRaisesRegex(QoSIntentError, "default QoS class"):
            normalize_qos_intent(
                {
                    "enabled": True,
                    "egress_limits_mbps": {"wan1": 100},
                    "classes": [
                        {"name": "default", "priority": 8, "bandwidth_percent": 100, "default": True, "dscp": [0]},
                    ],
                }
            )

    def test_identifier_injection_is_rejected(self):
        with self.assertRaisesRegex(QoSIntentError, "unsupported characters"):
            normalize_qos_intent(
                {
                    "enabled": True,
                    "egress_limits_mbps": {"wan1;remove": 100},
                    "classes": [
                        {"name": "default", "priority": 8, "bandwidth_percent": 100, "default": True, "dscp": []},
                    ],
                }
            )


if __name__ == "__main__":
    unittest.main()
