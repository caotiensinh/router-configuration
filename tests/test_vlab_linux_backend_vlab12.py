import unittest

from router_configuration.vlab_linux_backend import (
    LinuxBackendCapabilityError,
    cap_net_admin_from_capeff,
    select_linux_network_backend,
)


class VlabLinuxBackend12Tests(unittest.TestCase):
    def all_caps(self, **overrides):
        values = dict(
            platform_linux=True,
            cap_net_admin=True,
            ip_tool_available=True,
            network_namespace_supported=True,
            veth_supported=True,
            bridge_supported=True,
            vlan_supported=True,
        )
        values.update(overrides)
        return values

    def test_full_capability_selects_kernel_namespace_without_hardware_claim(self):
        result = select_linux_network_backend(self.all_caps()).as_dict()
        self.assertEqual(result["backend_kind"], "KernelNamespaceBackend")
        self.assertEqual(result["evidence_class"], "VIRTUAL_VERIFIED")
        self.assertTrue(result["kernel_namespace_validated"])
        self.assertFalse(result["hardware_verified"])
        self.assertFalse(result["production_write_authority"])

    def test_missing_capability_selects_deterministic_fallback(self):
        result = select_linux_network_backend(self.all_caps(cap_net_admin=False)).as_dict()
        self.assertEqual(result["backend_kind"], "DeterministicUserSpaceBackend")
        self.assertFalse(result["kernel_namespace_validated"])
        self.assertIn("cap_net_admin", result["missing_capabilities"])
        self.assertFalse(result["privilege_escalation_attempted"])

    def test_missing_unknown_or_non_boolean_facts_fail_closed(self):
        facts = self.all_caps()
        facts.pop("vlan_supported")
        with self.assertRaises(LinuxBackendCapabilityError):
            select_linux_network_backend(facts)
        with self.assertRaises(LinuxBackendCapabilityError):
            select_linux_network_backend({**self.all_caps(), "magic": True})
        with self.assertRaises(LinuxBackendCapabilityError):
            select_linux_network_backend(self.all_caps(cap_net_admin="yes"))

    def test_capeff_parser_detects_cap_net_admin_bit(self):
        self.assertTrue(cap_net_admin_from_capeff("1000"))
        self.assertFalse(cap_net_admin_from_capeff("0000"))
        with self.assertRaises(LinuxBackendCapabilityError):
            cap_net_admin_from_capeff("not-hex")


if __name__ == "__main__":
    unittest.main()
