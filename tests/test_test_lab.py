import unittest

from router_configuration.test_harness import CommonScenario
from router_configuration.test_lab import (
    FaultAction,
    FaultPlane,
    LabPortRole,
    StandardLabTopology,
    plan_common_fault,
)


class ReusableTestLabTests(unittest.TestCase):
    def test_standard_topology_has_four_stable_roles(self):
        topology = StandardLabTopology.build()
        payload = topology.as_dict()
        self.assertEqual(
            [item["role"] for item in payload["attachments"]],
            ["management", "wan_primary", "wan_backup", "lan"],
        )
        self.assertEqual([item["guest_order"] for item in payload["attachments"]], [0, 1, 2, 3])
        self.assertTrue(payload["management_isolated"])
        self.assertEqual(payload["vendor_management_addressing"], "adapter_defined")
        self.assertFalse(payload["physical_hardware_claimed"])
        self.assertFalse(payload["production_writer_available"])
        self.assertFalse(payload["write_authorized"])
        self.assertEqual(len(payload["topology_sha256"]), 64)

    def test_common_data_networks_match_existing_chr_lab_shape(self):
        topology = StandardLabTopology.build()
        by_role = {item.role: item for item in topology.attachments}
        self.assertEqual(by_role[LabPortRole.WAN_PRIMARY].network, "192.0.2.0/30")
        self.assertEqual(by_role[LabPortRole.WAN_PRIMARY].dut_address, "192.0.2.2")
        self.assertEqual(by_role[LabPortRole.WAN_BACKUP].network, "198.51.100.0/30")
        self.assertEqual(by_role[LabPortRole.LAN].network, "10.10.10.0/24")
        self.assertEqual(topology.service_ip, "203.0.113.100")
        self.assertEqual(topology.dns_ip, "203.0.113.53")

    def test_wan_blackhole_is_vendor_neutral_external_fault(self):
        plan = plan_common_fault(CommonScenario.WAN_FAILOVER)
        self.assertIs(plan.plane, FaultPlane.EXTERNAL_NETWORK)
        self.assertIs(plan.action, FaultAction.UPSTREAM_PACKET_BLACKHOLE)
        self.assertIs(plan.target_role, LabPortRole.WAN_PRIMARY)
        self.assertTrue(plan.reusable_across_vendors)
        self.assertFalse(plan.requires_vendor_adapter)
        self.assertFalse(plan.as_dict()["write_authorized"])

    def test_dns_stop_is_vendor_neutral_service_fault(self):
        plan = plan_common_fault(CommonScenario.DNS_FAILURE)
        self.assertIs(plan.plane, FaultPlane.SERVICE)
        self.assertIs(plan.action, FaultAction.DNS_RESPONDER_STOP)
        self.assertTrue(plan.reusable_across_vendors)
        self.assertFalse(plan.requires_vendor_adapter)

    def test_default_route_loss_is_explicitly_vendor_adapter_work(self):
        plan = plan_common_fault(CommonScenario.DEFAULT_ROUTE_LOSS)
        self.assertIs(plan.plane, FaultPlane.VENDOR_CONTROL_PLANE)
        self.assertIs(plan.action, FaultAction.DISABLE_OWNED_DEFAULT_ROUTE)
        self.assertFalse(plan.reusable_across_vendors)
        self.assertTrue(plan.requires_vendor_adapter)

    def test_unimplemented_common_fault_is_not_invented(self):
        with self.assertRaisesRegex(ValueError, "no common fault plan"):
            plan_common_fault(CommonScenario.PERFORMANCE_CAPACITY)


if __name__ == "__main__":
    unittest.main()
