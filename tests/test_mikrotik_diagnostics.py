import unittest

from router_configuration.vendors.mikrotik.diagnostics import build_diagnostic_plan
from router_configuration.vendors.mikrotik.tool_registry import MikroTikToolMode


class MikroTikDiagnosticsTests(unittest.TestCase):
    def test_diagnostic_plan_never_contains_write_tools(self):
        plan = build_diagnostic_plan(("internet", "routing", "firewall"))
        self.assertTrue(plan.tools)
        self.assertFalse(any(tool.mode in {MikroTikToolMode.WRITE, MikroTikToolMode.DESTRUCTIVE} for tool in plan.tools))
        self.assertFalse(plan.as_dict()["configuration_mutation_allowed"])

    def test_capture_is_separate_opt_in(self):
        normal = build_diagnostic_plan(("diagnostic",), include_capture=False)
        capture = build_diagnostic_plan(("diagnostic",), include_capture=True)
        self.assertFalse(any(tool.mode is MikroTikToolMode.CAPTURE for tool in normal.tools))
        self.assertTrue(any(tool.mode is MikroTikToolMode.CAPTURE for tool in capture.tools))


if __name__ == "__main__":
    unittest.main()
