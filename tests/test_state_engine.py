import unittest

from router_configuration.m02_state_engine import StateEngine
from router_configuration.types import OperationKind, RiskLevel


class StateEngineTests(unittest.TestCase):
    def test_plan_is_deterministic_and_detects_network_risk(self):
        desired = {
            "wan": {"wan1": {"weight": 10}, "wan2": {"weight": 1}},
            "qos": {"enabled": True},
        }
        actual = {
            "wan": {"wan1": {"weight": 1}, "wan2": {"weight": 1}},
            "qos": {"enabled": False},
        }

        engine = StateEngine()
        first = engine.build_plan(desired, actual)
        second = engine.build_plan(desired, actual)

        self.assertEqual(first.plan_id, second.plan_id)
        self.assertEqual(len(first.operations), 2)
        self.assertEqual(first.max_risk, RiskLevel.NETWORK_CHANGE)
        self.assertTrue(
            any(
                op.path == "wan.wan1.weight" and op.kind is OperationKind.UPDATE
                for op in first.operations
            )
        )

    def test_equal_state_is_noop(self):
        state = {"routing": {"enabled": True}}
        plan = StateEngine().build_plan(state, state)
        self.assertTrue(plan.is_noop)
        self.assertFalse(StateEngine().has_drift(state, state))


if __name__ == "__main__":
    unittest.main()
