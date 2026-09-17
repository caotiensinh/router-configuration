import unittest

from router_configuration.linux_network_backend import (
    LinuxNetworkCapabilities,
    cap_net_admin_from_status,
    probe_linux_network_capabilities,
    select_linux_network_backend,
)


class LinuxNetworkBackendVlab12Tests(unittest.TestCase):
    def test_cap_net_admin_parser_uses_effective_capability_bit(self):
        self.assertTrue(cap_net_admin_from_status("CapEff:\t0000000000001000\n"))
        self.assertFalse(cap_net_admin_from_status("CapEff:\t0000000000000000\n"))
        self.assertFalse(cap_net_admin_from_status("Name:\tpython\n"))

    def test_all_observed_capabilities_select_kernel_namespace_backend(self):
        caps = LinuxNetworkCapabilities(
            platform_linux=True,
            cap_net_admin=True,
            ip_tool_available=True,
            network_namespace_supported=True,
            veth_supported=True,
            bridge_supported=True,
            vlan_supported=True,
            unavailable_reasons=(),
        )
        selected = select_linux_network_backend(caps).as_dict()
        self.assertEqual(selected["backend_kind"], "KernelNamespaceBackend")
        self.assertTrue(selected["kernel_namespace_validation_available"])
        self.assertEqual(selected["evidence_ceiling"], "VIRTUAL_VERIFIED")
        self.assertFalse(selected["hardware_verified"])
        self.assertFalse(selected["production_write_authority"])

    def test_missing_capability_selects_deterministic_fallback_with_reason(self):
        caps = LinuxNetworkCapabilities(
            platform_linux=True,
            cap_net_admin=False,
            ip_tool_available=True,
            network_namespace_supported=True,
            veth_supported=True,
            bridge_supported=True,
            vlan_supported=True,
            unavailable_reasons=("cap_net_admin=false",),
        )
        selected = select_linux_network_backend(caps).as_dict()
        self.assertEqual(selected["backend_kind"], "DeterministicUserSpaceBackend")
        self.assertFalse(selected["kernel_namespace_validation_available"])
        self.assertIn("cap_net_admin=false", selected["unavailable_reasons"])
        self.assertFalse(selected["hardware_verified"])

    def test_runtime_probe_fails_closed_for_unobserved_feature_support(self):
        caps = probe_linux_network_capabilities()
        selected = select_linux_network_backend(caps).as_dict()
        self.assertEqual(selected["evidence_ceiling"], "VIRTUAL_VERIFIED")
        self.assertFalse(selected["hardware_verified"])
        if not (caps.veth_supported and caps.bridge_supported and caps.vlan_supported):
            self.assertEqual(selected["backend_kind"], "DeterministicUserSpaceBackend")
            self.assertFalse(selected["kernel_namespace_validation_available"])


if __name__ == "__main__":
    unittest.main()
