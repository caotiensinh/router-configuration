import unittest

from router_configuration.vendors.mikrotik.risk_policy import ToolRisk, classify_plan_risk, classify_tool_risk
from router_configuration.vendors.mikrotik.tool_registry import tool_by_name


class MikroTikRiskPolicyTests(unittest.TestCase):
    def test_read_only_is_non_mutating_risk(self):
        self.assertEqual(classify_tool_risk(tool_by_name("mikrotik.interface.list")), ToolRisk.NONE)

    def test_capture_is_separate_high_risk_capability(self):
        self.assertEqual(classify_tool_risk(tool_by_name("mikrotik.capture.torch")), ToolRisk.HIGH)

    def test_management_critical_write_is_critical(self):
        self.assertEqual(classify_tool_risk(tool_by_name("mikrotik.config.route.create")), ToolRisk.CRITICAL)

    def test_plan_uses_highest_member_risk(self):
        risk = classify_plan_risk((tool_by_name("mikrotik.interface.list"), tool_by_name("mikrotik.diag.ping")))
        self.assertEqual(risk, ToolRisk.LOW)


if __name__ == "__main__":
    unittest.main()
