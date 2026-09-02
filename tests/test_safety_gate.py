import unittest

from router_configuration.m02_state_engine import StateEngine
from router_configuration.m09_safety_gate import GateMode, SafetyContext, SafetyGate


class SafetyGateTests(unittest.TestCase):
    def test_network_change_is_denied_without_preconditions(self):
        plan = StateEngine().build_plan(
            {"routing": {"default_route": "wan1"}},
            {"routing": {"default_route": "wan2"}},
        )
        decision = SafetyGate().authorize_apply(
            plan,
            mode=GateMode.CHANGE,
            context=SafetyContext(production=True),
        )
        self.assertFalse(decision.allowed)
        self.assertGreaterEqual(len(decision.reasons), 3)

    def test_critical_change_requires_critical_approval(self):
        plan = StateEngine().build_plan(
            {"management": {"address": "192.168.11.1"}},
            {"management": {"address": "192.168.11.254"}},
        )
        base = dict(
            production=True,
            backup_available=True,
            management_path_verified=True,
            explicit_authorization=True,
        )
        denied = SafetyGate().authorize_apply(
            plan,
            mode=GateMode.CHANGE,
            context=SafetyContext(**base),
        )
        self.assertFalse(denied.allowed)

        allowed = SafetyGate().authorize_apply(
            plan,
            mode=GateMode.CHANGE,
            context=SafetyContext(**base, critical_approval=True),
        )
        self.assertTrue(allowed.allowed)


if __name__ == "__main__":
    unittest.main()
