import unittest

from router_configuration.vendors.cisco.network_sandbox_adapter import (
    normalize_switch_simulation_state,
)


class CiscoNetworkSandboxTrunkSemanticsTests(unittest.TestCase):
    def test_empty_trunk_vlan_list_means_all_vlans_allowed(self) -> None:
        snapshot = {
            "nodes": {
                "sw1": {
                    "kind": "switch",
                    "interfaces": {
                        "p2": {
                            "address": None,
                            "mode": "trunk",
                            "access_vlan": None,
                            "allowed_vlans": [],
                            "native_vlan": 10,
                            "vlan": None,
                        }
                    },
                    "routes": [],
                    "firewall_rules": 0,
                    "nat_rules": 0,
                    "default_firewall_action": "allow",
                }
            },
            "links": {},
            "conntrack": [],
        }

        state = normalize_switch_simulation_state(snapshot, node_name="sw1")
        trunk = state["interfaces"][0]
        self.assertEqual(trunk["allowed_vlans"], [])
        self.assertTrue(trunk["all_vlans_allowed"])
        self.assertFalse(state["live_acceptance"])
        self.assertFalse(state["canonical_acceptance_promoted"])


if __name__ == "__main__":
    unittest.main()
