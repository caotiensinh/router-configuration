import unittest

from router_configuration.vendors.mikrotik.tool_registry import tool_by_name, MikroTikTransport
from router_configuration.vendors.mikrotik.transport_policy import TransportRequirement, select_transport


class MikroTikTransportPolicyTests(unittest.TestCase):
    def test_continuous_operation_uses_native_api(self):
        torch = tool_by_name("mikrotik.capture.torch")
        self.assertEqual(select_transport(torch), MikroTikTransport.API)

    def test_interactive_session_uses_ssh_cli(self):
        tool = tool_by_name("mikrotik.interface.list")
        selected = select_transport(tool, TransportRequirement(interactive_session=True))
        self.assertEqual(selected, MikroTikTransport.SSH_CLI)

    def test_one_shot_read_keeps_validated_preference(self):
        tool = tool_by_name("mikrotik.interface.list")
        self.assertEqual(select_transport(tool), tool.preferred_transport)


if __name__ == "__main__":
    unittest.main()
