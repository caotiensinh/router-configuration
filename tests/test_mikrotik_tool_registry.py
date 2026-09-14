import unittest

from router_configuration.mikrotik_tool_registry import (
    MikroTikToolMode,
    mikrotik_tool_catalog,
    tools_for_intent,
)


class MikroTikToolRegistryTests(unittest.TestCase):
    def test_catalog_names_are_unique(self):
        tools = mikrotik_tool_catalog()
        self.assertEqual(len({tool.name for tool in tools}), len(tools))

    def test_default_intent_selection_never_loads_write_or_capture_tools(self):
        tools = tools_for_intent("secure_internet_gateway")
        self.assertTrue(tools)
        self.assertFalse(any(tool.mutates_configuration for tool in tools))
        self.assertFalse(any(tool.mode is MikroTikToolMode.CAPTURE for tool in tools))

    def test_site_to_site_can_explicitly_request_write_tools(self):
        tools = tools_for_intent("site_to_site_wireguard", include_writes=True)
        names = {tool.name for tool in tools}
        self.assertIn("mikrotik.config.wireguard.interface.create", names)
        self.assertIn("mikrotik.config.wireguard.peer.create", names)
        self.assertIn("mikrotik.config.route.create", names)
        self.assertTrue(
            all(
                tool.requires_explicit_write_gate
                for tool in tools
                if tool.mutates_configuration
            )
        )

    def test_capture_tools_require_separate_opt_in(self):
        normal = tools_for_intent("secure_internet_gateway", include_capture=False)
        capture = tools_for_intent("secure_internet_gateway", include_capture=True)
        self.assertFalse(any(tool.mode is MikroTikToolMode.CAPTURE for tool in normal))
        self.assertTrue(any(tool.mode is MikroTikToolMode.CAPTURE for tool in capture))


if __name__ == "__main__":
    unittest.main()
