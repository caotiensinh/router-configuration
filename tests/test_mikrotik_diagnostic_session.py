import unittest

from router_configuration.vendors.mikrotik.diagnostic_session import build_diagnostic_session
from router_configuration.vendors.mikrotik.privilege_profiles import PrivilegeProfileKind
from router_configuration.vendors.mikrotik.risk_policy import ToolRisk


class MikroTikDiagnosticSessionTests(unittest.TestCase):
    def test_default_session_is_non_authorizing_and_no_capture_escalation(self):
        session = build_diagnostic_session("client_no_internet")
        payload = session.as_dict()
        self.assertFalse(payload["write_authorized"])
        self.assertEqual(session.privilege_profile.kind, PrivilegeProfileKind.DIAGNOSTIC)
        self.assertLessEqual(session.risk, ToolRisk.LOW)

    def test_capture_requires_explicit_session_opt_in(self):
        normal = build_diagnostic_session("client_no_internet")
        elevated = build_diagnostic_session("client_no_internet", include_capture=True)
        self.assertEqual(normal.privilege_profile.kind, PrivilegeProfileKind.DIAGNOSTIC)
        self.assertEqual(elevated.privilege_profile.kind, PrivilegeProfileKind.CAPTURE)
        self.assertGreaterEqual(elevated.risk, ToolRisk.HIGH)
        self.assertFalse(elevated.as_dict()["write_authorized"])


if __name__ == "__main__":
    unittest.main()
