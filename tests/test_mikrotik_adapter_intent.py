import unittest

from router_configuration.adapters.mikrotik import MikroTikReferenceAdapter


class MikroTikAdapterIntentTests(unittest.TestCase):
    def test_adapter_exposes_intent_compiler_without_write_authority(self):
        adapter = MikroTikReferenceAdapter()
        plan = adapter.compile_operator_intent(
            {
                "kind": "secure_internet_gateway",
                "lan_cidr": "192.168.10.0/24",
                "lan_interface": "bridge-lan",
                "wan_interface": "ether1",
            }
        )
        self.assertTrue(plan.ready_for_planning)
        self.assertFalse(plan.write_authorized)

    def test_write_tool_metadata_is_visible_only_on_explicit_request(self):
        adapter = MikroTikReferenceAdapter()
        default = adapter.tools_for_intent("site_to_site_wireguard")
        review = adapter.tools_for_intent(
            "site_to_site_wireguard",
            include_writes=True,
        )
        self.assertFalse(any(tool.mutates_configuration for tool in default))
        self.assertTrue(any(tool.mutates_configuration for tool in review))


if __name__ == "__main__":
    unittest.main()
