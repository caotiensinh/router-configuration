import unittest

from router_configuration.vendors.mikrotik.privilege_profiles import (
    PrivilegeProfileKind,
    build_privilege_profile,
)
from router_configuration.vendors.mikrotik.tool_registry import tool_by_name


class MikroTikPrivilegeProfileTests(unittest.TestCase):
    def test_diagnostic_profile_aggregates_only_needed_policies(self):
        tools = (
            tool_by_name("mikrotik.interface.list"),
            tool_by_name("mikrotik.diag.ping"),
        )
        profile = build_privilege_profile(PrivilegeProfileKind.DIAGNOSTIC, tools)
        self.assertIn("read", profile.policies)
        self.assertIn("test", profile.policies)
        self.assertNotIn("write", profile.policies)
        self.assertFalse(profile.unrestricted_admin)

    def test_read_only_profile_rejects_write_tool(self):
        with self.assertRaises(ValueError):
            build_privilege_profile(
                PrivilegeProfileKind.READ_ONLY,
                (tool_by_name("mikrotik.config.route.create"),),
            )

    def test_diagnostic_profile_rejects_capture_privilege(self):
        with self.assertRaises(ValueError):
            build_privilege_profile(
                PrivilegeProfileKind.DIAGNOSTIC,
                (tool_by_name("mikrotik.capture.torch"),),
            )


if __name__ == "__main__":
    unittest.main()
