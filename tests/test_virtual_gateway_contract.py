import unittest

from router_configuration.virtual_gateway_contract import VirtualGatewayContract, VirtualGatewayContractError


class VirtualGatewayContractTests(unittest.TestCase):
    def make_gateway(self):
        gateway = VirtualGatewayContract(
            verified_capabilities={"INTERFACES", "STATIC_ROUTING", "FORWARDING", "FIREWALL"}
        )
        gateway.add_interface(name="lan", cidr="192.168.10.1/24", role="LAN")
        gateway.add_interface(name="wan", cidr="10.0.0.2/24", role="WAN")
        return gateway

    def test_connected_route_forwards_virtually(self):
        decision = self.make_gateway().forward("192.168.10.55").as_dict()
        self.assertTrue(decision["forwarded"])
        self.assertEqual(decision["egress_interface"], "lan")
        self.assertEqual(decision["evidence_class"], "VIRTUAL_VERIFIED")
        self.assertFalse(decision["hardware_verified"])

    def test_static_route_uses_reachable_next_hop(self):
        gateway = self.make_gateway()
        gateway.add_static_route(destination="172.16.0.0/16", next_hop="10.0.0.1", metric=10)
        decision = gateway.forward("172.16.10.20").as_dict()
        self.assertTrue(decision["forwarded"])
        self.assertEqual(decision["egress_interface"], "wan")
        self.assertEqual(decision["reason"], "STATIC_ROUTE")

    def test_firewall_block_precedes_route(self):
        gateway = self.make_gateway()
        gateway.block_destination("192.168.10.128/25")
        decision = gateway.forward("192.168.10.200").as_dict()
        self.assertFalse(decision["forwarded"])
        self.assertEqual(decision["reason"], "FIREWALL_BLOCK")

    def test_overlapping_interfaces_are_rejected(self):
        gateway = self.make_gateway()
        with self.assertRaises(VirtualGatewayContractError):
            gateway.add_interface(name="lan2", cidr="192.168.10.2/25", role="LAN")

    def test_unknown_capability_is_rejected(self):
        with self.assertRaises(VirtualGatewayContractError):
            VirtualGatewayContract(verified_capabilities={"MAGIC_NAT"})


if __name__ == "__main__":
    unittest.main()
