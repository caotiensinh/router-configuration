import unittest

from router_configuration.virtual_ap_bridge_contract import VirtualAP, VirtualBridge, VirtualApBridgeError


class VirtualApBridgeContractTests(unittest.TestCase):
    def test_virtual_ap_association_carries_verified_vlan_mapping(self):
        ap = VirtualAP(verified_capabilities={"SSID", "RADIO_STATE", "CLIENT_ASSOCIATION", "VLAN_MAPPING"})
        ap.add_ssid(ssid="guest", vlan_id=20)
        ap.set_radio(True)
        association = ap.associate(client_id="client-1", ssid="guest")
        self.assertEqual(association.vlan_id, 20)
        self.assertFalse(ap.snapshot()["hardware_verified"])

    def test_virtual_ap_radio_down_blocks_association(self):
        ap = VirtualAP(verified_capabilities={"SSID", "RADIO_STATE", "CLIENT_ASSOCIATION", "VLAN_MAPPING"})
        ap.add_ssid(ssid="guest", vlan_id=20)
        with self.assertRaises(VirtualApBridgeError):
            ap.associate(client_id="client-1", ssid="guest")

    def test_virtual_bridge_forwards_only_admitted_vlan(self):
        bridge = VirtualBridge(verified_capabilities={"BRIDGE_FORWARDING", "VLAN_8021Q", "LINK_STATE"})
        bridge.add_port(name="p1", link_up=True, vlans={10, 20})
        bridge.add_port(name="p2", link_up=True, vlans={20})
        allowed = bridge.forward(ingress_port="p1", egress_port="p2", vlan_id=20)
        denied = bridge.forward(ingress_port="p1", egress_port="p2", vlan_id=10)
        self.assertTrue(allowed["forwarded"])
        self.assertFalse(denied["forwarded"])
        self.assertEqual(denied["reason"], "EGRESS_VLAN_NOT_ADMITTED")

    def test_unknown_ap_capability_is_rejected(self):
        with self.assertRaises(VirtualApBridgeError):
            VirtualAP(verified_capabilities={"MAGIC_ROAMING"})

    def test_unknown_bridge_capability_is_rejected(self):
        with self.assertRaises(VirtualApBridgeError):
            VirtualBridge(verified_capabilities={"MAGIC_BRIDGE"})


if __name__ == "__main__":
    unittest.main()
