import unittest

from router_configuration.vlan_intent import VlanIntentError, normalize_vlan_intent


def valid_intent():
    return {
        "enabled": True,
        "bridge": "bridge-core",
        "vlans": [
            {"id": 10, "name": "users"},
            {"id": 99, "name": "management"},
        ],
        "ports": [
            {"interface": "ether2", "mode": "access", "access_vlan": 10},
            {"interface": "ether3", "mode": "access", "access_vlan": 99},
            {"interface": "sfp-sfpplus2", "mode": "trunk", "allowed_vlans": [10, 99]},
        ],
        "management": {
            "vlan_id": 99,
            "port": "ether3",
            "address": "192.168.99.1/24",
        },
    }


class VlanIntentTests(unittest.TestCase):
    def test_normalization_pins_safe_frame_types_and_activation_order(self):
        result = normalize_vlan_intent(valid_intent()).attributes
        self.assertEqual(result["activation_order"], "management_first_vlan_filtering_last")
        self.assertTrue(result["vlan_filtering"])
        access = next(item for item in result["ports"] if item["interface"] == "ether2")
        trunk = next(item for item in result["ports"] if item["interface"] == "sfp-sfpplus2")
        self.assertEqual(access["frame_types"], "admit-only-untagged-and-priority-tagged")
        self.assertEqual(trunk["frame_types"], "admit-only-vlan-tagged")
        self.assertTrue(access["ingress_filtering"])
        self.assertTrue(trunk["ingress_filtering"])

    def test_vlan_one_is_not_accepted_as_managed_segment(self):
        intent = valid_intent()
        intent["vlans"][0]["id"] = 1
        with self.assertRaisesRegex(VlanIntentError, "2 to 4094"):
            normalize_vlan_intent(intent)

    def test_management_access_port_must_match_management_vlan(self):
        intent = valid_intent()
        intent["management"]["port"] = "ether2"
        with self.assertRaisesRegex(VlanIntentError, "PVID"):
            normalize_vlan_intent(intent)

    def test_management_trunk_must_explicitly_allow_management_vlan(self):
        intent = valid_intent()
        intent["management"]["port"] = "sfp-sfpplus2"
        intent["ports"][2]["allowed_vlans"] = [10]
        with self.assertRaisesRegex(VlanIntentError, "management trunk"):
            normalize_vlan_intent(intent)

    def test_access_port_cannot_mix_allowed_vlan_semantics(self):
        intent = valid_intent()
        intent["ports"][0]["allowed_vlans"] = [10]
        with self.assertRaisesRegex(VlanIntentError, "must not declare allowed_vlans"):
            normalize_vlan_intent(intent)

    def test_trunk_port_cannot_mix_access_vlan_semantics(self):
        intent = valid_intent()
        intent["ports"][2]["access_vlan"] = 99
        with self.assertRaisesRegex(VlanIntentError, "must not declare access_vlan"):
            normalize_vlan_intent(intent)

    def test_undeclared_vlan_membership_is_rejected(self):
        intent = valid_intent()
        intent["ports"][2]["allowed_vlans"].append(777)
        with self.assertRaisesRegex(VlanIntentError, "undeclared VLAN"):
            normalize_vlan_intent(intent)

    def test_duplicate_port_is_rejected(self):
        intent = valid_intent()
        intent["ports"].append(
            {"interface": "ether2", "mode": "access", "access_vlan": 10}
        )
        with self.assertRaisesRegex(VlanIntentError, "duplicate VLAN port"):
            normalize_vlan_intent(intent)

    def test_identifier_injection_is_rejected(self):
        intent = valid_intent()
        intent["bridge"] = "bridge-core;remove"
        with self.assertRaisesRegex(VlanIntentError, "unsupported characters"):
            normalize_vlan_intent(intent)


if __name__ == "__main__":
    unittest.main()
