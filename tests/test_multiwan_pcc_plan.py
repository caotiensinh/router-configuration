import unittest
from collections import Counter

from router_configuration.m04_multiwan import MultiWanPlanner, WanLink, WeightedWanPolicy


class MultiWanPccPlanTests(unittest.TestCase):
    def test_10g_plus_1g_compiles_exact_10_to_1_pcc_buckets(self):
        planner = MultiWanPlanner()
        policy = planner.derive_capacity_weights(
            [WanLink("wan10g", 10000), WanLink("wan1g", 1000)]
        )
        buckets = planner.build_pcc_buckets(policy)

        self.assertEqual(len(buckets), 11)
        self.assertEqual({bucket.denominator for bucket in buckets}, {11})
        self.assertEqual([bucket.remainder for bucket in buckets], list(range(11)))
        self.assertEqual(
            Counter(bucket.wan_name for bucket in buckets),
            {"wan10g": 10, "wan1g": 1},
        )
        self.assertEqual({bucket.classifier for bucket in buckets}, {f"11/{i}" for i in range(11)})

    def test_pcc_rule_explosion_is_rejected_instead_of_silently_generated(self):
        planner = MultiWanPlanner()
        policy = WeightedWanPolicy(("wan-a", 101), ("wan-b", 100))
        with self.assertRaisesRegex(ValueError, "exceeds safe bucket limit"):
            planner.build_pcc_buckets(policy, max_buckets=64)

    def test_weighted_policy_rejects_duplicate_or_nonpositive_inputs(self):
        with self.assertRaises(ValueError):
            WeightedWanPolicy((("wan-a", 1), ("wan-a", 1)))
        with self.assertRaises(ValueError):
            WeightedWanPolicy((("wan-a", 0),))


if __name__ == "__main__":
    unittest.main()
