import unittest

from router_configuration.virtual_switch_contract import VirtualSwitchContract, VirtualSwitchContractError


class VirtualSwitchContractTests(unittest.TestCase):
    def make_switch(self):
        sw = VirtualSwitchContract(verified_capabilities={"VLAN_8021Q", "PVID", "LINK_STATE", "FORWARDING"})
        sw.configure_port(name="p1", link_up=True, pvid=10, tagged_vlans={20}, untagged_vlans={10})
        sw.configure_port(name="p2", link_up=True, pvid=10, tagged_vlans={20}, untagged_vlans={10})
        return sw

    def test_untagged_ingress_uses_pvid_and_forwards_untagged(self):
        decision = self.make_switch().forward(ingress_port="p1", egress_port="p2", tagged=False).as_dict()
        self.assertTrue(decision["forwarded"])
        self.assertEqual(decision["vlan_id"], 10)
        self.assertFalse(decision["egress_tagged"])
        self.assertEqual(decision["evidence_class"], "VIRTUAL_VERIFIED")
        self.assertFalse(decision["hardware_verified"])

    def test_tagged_vlan_forwards_only_when_admitted(self):
        decision = self.make_switch().forward(ingress_port="p1", egress_port="p2", tagged=True, vlan_id=20).as_dict()
        self.assertTrue(decision["forwarded"])
        self.assertTrue(decision["egress_tagged"])

    def test_unverified_capability_is_rejected(self):
        with self.assertRaises(VirtualSwitchContractError):
            VirtualSwitchContract(verified_capabilities={"MAGIC_STP"})

    def test_missing_forwarding_capability_fails_closed(self):
        sw = VirtualSwitchContract(verified_capabilities={"VLAN_8021Q", "PVID", "LINK_STATE"})
        sw.configure_port(name="p1", link_up=True, pvid=10, tagged_vlans=set(), untagged_vlans={10})
        sw.configure_port(name="p2", link_up=True, pvid=10, tagged_vlans=set(), untagged_vlans={10})
        with self.assertRaises(VirtualSwitchContractError):
            sw.forward(ingress_port="p1", egress_port="p2", tagged=False)

    def test_link_down_blocks_forwarding(self):
        sw = VirtualSwitchContract(verified_capabilities={"VLAN_8021Q", "PVID", "LINK_STATE", "FORWARDING"})
        sw.configure_port(name="p1", link_up=False, pvid=10, tagged_vlans=set(), untagged_vlans={10})
        sw.configure_port(name="p2", link_up=True, pvid=10, tagged_vlans=set(), untagged_vlans={10})
        decision = sw.forward(ingress_port="p1", egress_port="p2", tagged=False).as_dict()
        self.assertFalse(decision["forwarded"])
        self.assertEqual(decision["reason"], "LINK_DOWN")


if __name__ == "__main__":
    unittest.main()
