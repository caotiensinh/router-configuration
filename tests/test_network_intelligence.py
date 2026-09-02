import unittest
from collections import Counter

from router_configuration.m04_multiwan import MultiWanPlanner, WanLink
from router_configuration.m05_resilience import (
    HealthPolicy,
    ProbeKind,
    ProbeResult,
    ResilienceEngine,
    WanHealthState,
)
from router_configuration.m06_security import (
    SecurityBaseline,
    SecurityPolicyValidator,
)
from router_configuration.m07_traffic_policy import (
    InterZoneRule,
    PolicyRoute,
    QosClass,
    TrafficPolicy,
    TrafficPolicyValidator,
    Zone,
)


class MultiWanTests(unittest.TestCase):
    def test_10g_plus_1g_derives_10_to_1_weight(self):
        planner = MultiWanPlanner()
        policy = planner.derive_capacity_weights(
            [
                WanLink("wan10g", 10000),
                WanLink("wan1g", 1000),
            ]
        )
        self.assertEqual(policy.weight_for("wan10g"), 10)
        self.assertEqual(policy.weight_for("wan1g"), 1)

        buckets = planner.allocate_buckets(policy, bucket_count=110)
        counts = Counter(buckets)
        self.assertEqual(counts["wan10g"], 100)
        self.assertEqual(counts["wan1g"], 10)


class ResilienceTests(unittest.TestCase):
    def test_link_up_is_not_enough_for_health(self):
        engine = ResilienceEngine()
        score = engine.score(
            [
                ProbeResult(ProbeKind.GATEWAY, True, weight=1),
                ProbeResult(ProbeKind.INTERNET, False, weight=2),
                ProbeResult(ProbeKind.DNS, False, weight=1),
                ProbeResult(ProbeKind.HTTPS, False, weight=1),
            ]
        )
        self.assertEqual(score, 20.0)
        decision = engine.decide(
            WanHealthState.HEALTHY,
            score,
            HealthPolicy(down_below=40, healthy_at_or_above=80),
        )
        self.assertEqual(decision.current, WanHealthState.DOWN)

    def test_down_state_requires_recovery_threshold(self):
        engine = ResilienceEngine()
        still_down = engine.decide(WanHealthState.DOWN, 79)
        recovered = engine.decide(WanHealthState.DOWN, 80)
        self.assertEqual(still_down.current, WanHealthState.DOWN)
        self.assertEqual(recovered.current, WanHealthState.HEALTHY)


class SecurityTests(unittest.TestCase):
    def test_open_management_access_is_blocking(self):
        validator = SecurityPolicyValidator()
        findings = validator.validate(
            SecurityBaseline(management_sources=("0.0.0.0/0",))
        )
        self.assertTrue(validator.has_blocking_findings(findings))

    def test_bounded_management_source_passes_baseline(self):
        validator = SecurityPolicyValidator()
        findings = validator.validate(
            SecurityBaseline(management_sources=("192.168.50.0/24",))
        )
        self.assertFalse(validator.has_blocking_findings(findings))


class TrafficPolicyTests(unittest.TestCase):
    def test_valid_camera_server_policy(self):
        policy = TrafficPolicy(
            zones=(
                Zone("camera", "192.168.20.0/24", internet_access=False),
                Zone("server", "192.168.30.0/24"),
            ),
            interzone_rules=(InterZoneRule("camera", "server", True),),
            policy_routes=(
                PolicyRoute(
                    "server-primary-10g",
                    source_zone="server",
                    preferred_wan="wan10g",
                    fallback_wan="wan1g",
                ),
            ),
            qos_classes=(
                QosClass("interactive", priority=1, tags=("dns", "vpn", "voice")),
                QosClass("bulk", priority=6, tags=("backup", "download")),
            ),
        )
        self.assertEqual(TrafficPolicyValidator().validate(policy), ())

    def test_overlap_is_rejected(self):
        policy = TrafficPolicy(
            zones=(
                Zone("a", "192.168.10.0/24"),
                Zone("b", "192.168.10.128/25"),
            )
        )
        self.assertTrue(TrafficPolicyValidator().validate(policy))


if __name__ == "__main__":
    unittest.main()
