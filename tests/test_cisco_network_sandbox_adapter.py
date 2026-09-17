import copy
import unittest

from router_configuration.vendors.cisco.network_sandbox_adapter import (
    C05_LOGIC_STATUS,
    C06_LOGIC_STATUS,
    C10_LOGIC_STATUS,
    CiscoNetworkSandboxAdapterError,
    build_network_sandbox_logic_evidence,
    evaluate_recovery_simulation,
    normalize_router_simulation_state,
    normalize_switch_simulation_state,
)
from router_configuration.vendors.cisco.simulation_evidence import (
    validate_simulation_evidence,
)


ROUTER_CONFIGURATION_SHA = "662cd0b2ea0ace82b422274aef8939c5c981f865"
NETWORK_SANDBOX_SHA = "e933712b9add6ee089fb57bddc014aab945b1fd5"


def sandbox_snapshot() -> dict:
    return {
        "nodes": {
            "edge": {
                "kind": "router",
                "interfaces": {
                    "lan0": {
                        "address": "192.168.10.1/24",
                        "mode": "routed",
                        "access_vlan": None,
                        "allowed_vlans": [],
                        "native_vlan": None,
                        "vlan": None,
                    },
                    "wan0": {
                        "address": "203.0.113.2/30",
                        "mode": "routed",
                        "access_vlan": None,
                        "allowed_vlans": [],
                        "native_vlan": None,
                        "vlan": None,
                    },
                },
                "routes": [{
                    "destination": "0.0.0.0/0",
                    "out_interface": "wan0",
                    "next_hop": "203.0.113.1",
                    "metric": 1,
                }],
                "firewall_rules": 3,
                "nat_rules": 2,
                "default_firewall_action": "allow",
            },
            "sw1": {
                "kind": "switch",
                "interfaces": {
                    "p1": {
                        "address": None,
                        "mode": "access",
                        "access_vlan": 10,
                        "allowed_vlans": [],
                        "native_vlan": None,
                        "vlan": None,
                    },
                    "p2": {
                        "address": None,
                        "mode": "trunk",
                        "access_vlan": None,
                        "allowed_vlans": [20, 10],
                        "native_vlan": 10,
                        "vlan": None,
                    },
                },
                "routes": [],
                "firewall_rules": 0,
                "nat_rules": 0,
                "default_firewall_action": "allow",
            },
            "internet": {
                "kind": "internet",
                "interfaces": {
                    "edge0": {
                        "address": "203.0.113.1/30",
                        "mode": "routed",
                        "access_vlan": None,
                        "allowed_vlans": [],
                        "native_vlan": None,
                        "vlan": None,
                    }
                },
                "routes": [],
                "firewall_rules": 0,
                "nat_rules": 0,
                "default_firewall_action": "allow",
            },
        },
        "links": {
            "sw1-edge": {
                "a": "sw1:p1",
                "b": "edge:lan0",
                "up": True,
                "latency_ms": 0.0,
                "loss_pct": 0.0,
            },
            "edge-internet": {
                "a": "edge:wan0",
                "b": "internet:edge0",
                "up": True,
                "latency_ms": 20.0,
                "loss_pct": 0.0,
            },
        },
        "conntrack": [],
    }


class CiscoNetworkSandboxAdapterTests(unittest.TestCase):
    def test_router_subset_is_normalized_without_live_promotion(self) -> None:
        state = normalize_router_simulation_state(
            sandbox_snapshot(), node_name="edge"
        )
        self.assertEqual(state["logic_status"], C05_LOGIC_STATUS)
        self.assertFalse(state["live_acceptance"])
        self.assertFalse(state["canonical_acceptance_promoted"])
        self.assertEqual(state["interfaces"][0]["name"], "lan0")
        self.assertEqual(state["interfaces"][0]["ipv4_cidr"], "192.168.10.1/24")
        self.assertTrue(state["interfaces"][0]["link_up"])
        self.assertEqual(state["routes"][0]["destination"], "0.0.0.0/0")
        self.assertIn("live IOS XE YANG inventory", state["coverage_gaps"])
        self.assertEqual(len(state["state_digest_sha256"]), 64)

    def test_switch_subset_validates_access_and_trunk_semantics(self) -> None:
        state = normalize_switch_simulation_state(
            sandbox_snapshot(), node_name="sw1"
        )
        self.assertEqual(state["logic_status"], C06_LOGIC_STATUS)
        self.assertFalse(state["live_acceptance"])
        access, trunk = state["interfaces"]
        self.assertEqual(access["mode"], "access")
        self.assertEqual(access["access_vlan"], 10)
        self.assertEqual(trunk["mode"], "trunk")
        self.assertEqual(trunk["allowed_vlans"], [10, 20])
        self.assertEqual(trunk["native_vlan"], 10)
        self.assertFalse(trunk["all_vlans_allowed"])
        self.assertIn("live IOS XE MAC table", state["coverage_gaps"])
        self.assertIn("live IOS XE STP operational state", state["coverage_gaps"])

    def test_recovery_requires_observed_fault_and_exact_restore(self) -> None:
        pre = sandbox_snapshot()
        fault = copy.deepcopy(pre)
        fault["links"]["edge-internet"]["up"] = False
        recovered = copy.deepcopy(pre)

        result = evaluate_recovery_simulation(pre, fault, recovered)
        self.assertTrue(result["fault_observed"])
        self.assertTrue(result["restored_exactly"])
        self.assertTrue(result["logic_pass"])
        self.assertEqual(result["logic_status"], C10_LOGIC_STATUS)
        self.assertFalse(result["live_acceptance"])

    def test_recovery_without_fault_fails_logic_gate(self) -> None:
        pre = sandbox_snapshot()
        result = evaluate_recovery_simulation(pre, copy.deepcopy(pre), copy.deepcopy(pre))
        self.assertFalse(result["fault_observed"])
        self.assertFalse(result["logic_pass"])
        self.assertEqual(result["logic_status"], "SIMULATION_FAIL")

    def test_recovery_without_exact_restore_fails_logic_gate(self) -> None:
        pre = sandbox_snapshot()
        fault = copy.deepcopy(pre)
        fault["links"]["edge-internet"]["up"] = False
        recovered = copy.deepcopy(pre)
        recovered["links"]["edge-internet"]["latency_ms"] = 21.0
        result = evaluate_recovery_simulation(pre, fault, recovered)
        self.assertTrue(result["fault_observed"])
        self.assertFalse(result["restored_exactly"])
        self.assertFalse(result["logic_pass"])

    def test_wrong_node_kind_and_malformed_vlan_fail_closed(self) -> None:
        with self.assertRaisesRegex(
            CiscoNetworkSandboxAdapterError, "kind=router"
        ):
            normalize_router_simulation_state(sandbox_snapshot(), node_name="sw1")

        broken = sandbox_snapshot()
        broken["nodes"]["sw1"]["interfaces"]["p1"]["access_vlan"] = 4095
        with self.assertRaisesRegex(
            CiscoNetworkSandboxAdapterError, "invalid VLAN id"
        ):
            normalize_switch_simulation_state(broken, node_name="sw1")

    def test_sensitive_field_is_rejected_before_processing(self) -> None:
        broken = sandbox_snapshot()
        broken["nodes"]["edge"]["password"] = "must-not-enter-evidence"
        with self.assertRaisesRegex(
            CiscoNetworkSandboxAdapterError, "sensitive field"
        ):
            normalize_router_simulation_state(broken, node_name="edge")

    def test_cross_repo_evidence_is_exact_sha_bound_and_simulation_only(self) -> None:
        pre = sandbox_snapshot()
        post = copy.deepcopy(pre)
        post["links"]["edge-internet"]["up"] = False
        evidence = build_network_sandbox_logic_evidence(
            router_configuration_sha=ROUTER_CONFIGURATION_SHA,
            network_sandbox_sha=NETWORK_SANDBOX_SHA,
            simulation_profile="cisco-c05-c06-c10-logic-v1",
            scenario={"name": "vlan-stateful-nat"},
            input_payload={"router": "edge", "switch": "sw1"},
            pre_snapshot=pre,
            post_snapshot=post,
            evidence_refs=[
                "github-actions:Network_Sandbox_Runtime:35172921884:attempt-2"
            ],
            tested_logic=[
                "C05 router normalized-state subset",
                "C06 switch access/trunk normalized-state subset",
                "C10 fault and exact recovery logic",
            ],
        )
        validate_simulation_evidence(evidence)
        self.assertEqual(
            evidence["router_configuration_sha"], ROUTER_CONFIGURATION_SHA
        )
        self.assertEqual(evidence["network_sandbox_sha"], NETWORK_SANDBOX_SHA)
        self.assertEqual(evidence["environment_kind"], "qualified_simulation")
        self.assertFalse(evidence["canonical_acceptance_promoted"])
        self.assertEqual(evidence["claimed_acceptance_gates"], [])


if __name__ == "__main__":
    unittest.main()
