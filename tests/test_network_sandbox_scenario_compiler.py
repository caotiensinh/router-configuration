import copy
import unittest

from router_configuration.network_sandbox_scenario_compiler import (
    COMPILED_SCHEMA,
    REQUEST_SCHEMA,
    NetworkSandboxScenarioCompileError,
    compile_network_sandbox_scenario,
    validate_compiled_network_sandbox_scenario,
)


NETWORK_SANDBOX_SHA = "a9658656efa3b20ae233b1be92d99fda70de4fcc"


def request_fixture():
    return {
        "schema_version": REQUEST_SCHEMA,
        "network_sandbox_sha": NETWORK_SANDBOX_SHA,
        "scenario_id": "routing-baseline-v1",
        "nodes": [
            {
                "name": "client",
                "kind": "host",
                "interfaces": [
                    {"name": "eth0", "address": "192.168.10.10/24"}
                ],
                "routes": [
                    {
                        "destination": "0.0.0.0/0",
                        "out_interface": "eth0",
                        "next_hop": "192.168.10.1",
                    }
                ],
            },
            {
                "name": "edge",
                "kind": "router",
                "interfaces": [
                    {"name": "lan0", "address": "192.168.10.1/24"},
                    {"name": "wan0", "address": "203.0.113.2/30"},
                ],
                "routes": [
                    {
                        "destination": "0.0.0.0/0",
                        "out_interface": "wan0",
                        "next_hop": "203.0.113.1",
                        "metric": 1,
                    }
                ],
            },
            {
                "name": "internet",
                "kind": "internet",
                "interfaces": [
                    {"name": "edge0", "address": "203.0.113.1/30"},
                    {"name": "service0", "address": "198.51.100.1/24"},
                ],
                "routes": [
                    {
                        "destination": "192.168.10.0/24",
                        "out_interface": "edge0",
                        "next_hop": "203.0.113.2",
                    }
                ],
            },
        ],
        "links": [
            {
                "name": "client-edge",
                "endpoints": ["client:eth0", "edge:lan0"],
            },
            {
                "name": "edge-internet",
                "endpoints": ["edge:wan0", "internet:edge0"],
                "latency_ms": 20,
            },
        ],
        "tests": [
            {
                "name": "client-reaches-internet",
                "src_node": "client",
                "dst_ip": "198.51.100.1",
                "protocol": "icmp",
                "expect": "reachable",
            }
        ],
    }


class NetworkSandboxScenarioCompilerTests(unittest.TestCase):
    def test_compiles_exact_network_sandbox_v1_shape(self):
        compiled = compile_network_sandbox_scenario(request_fixture()).as_dict()

        self.assertEqual(compiled["schema_version"], COMPILED_SCHEMA)
        self.assertEqual(compiled["network_sandbox_sha"], NETWORK_SANDBOX_SHA)
        self.assertEqual(compiled["network_sandbox_scenario_schema_version"], 1)
        self.assertEqual(compiled["evidence_class_ceiling"], "VIRTUAL_VERIFIED")
        self.assertFalse(compiled["hardware_present"])
        self.assertFalse(compiled["hardware_verified"])
        self.assertFalse(compiled["physical_device_verified"])
        self.assertFalse(compiled["production_write_authorized"])
        self.assertFalse(compiled["production_writer_available"])

        scenario = compiled["scenario"]
        self.assertEqual(set(scenario), {"schema_version", "topology", "tests"})
        self.assertEqual(scenario["schema_version"], 1)
        self.assertEqual(set(scenario["topology"]), {"nodes", "links"})
        self.assertEqual(
            [node["name"] for node in scenario["topology"]["nodes"]],
            ["client", "edge", "internet"],
        )
        self.assertEqual(
            [link["name"] for link in scenario["topology"]["links"]],
            ["client-edge", "edge-internet"],
        )
        self.assertEqual(
            scenario["tests"][0],
            {
                "name": "client-reaches-internet",
                "src_node": "client",
                "dst_ip": "198.51.100.1",
                "protocol": "icmp",
                "expect": "reachable",
            },
        )
        validate_compiled_network_sandbox_scenario(compiled)

    def test_compile_is_deterministic_for_equivalent_node_and_link_order(self):
        first = request_fixture()
        second = request_fixture()
        second["nodes"] = list(reversed(second["nodes"]))
        second["links"] = list(reversed(second["links"]))

        first_compiled = compile_network_sandbox_scenario(first).as_dict()
        second_compiled = compile_network_sandbox_scenario(second).as_dict()

        self.assertEqual(
            first_compiled["scenario"],
            second_compiled["scenario"],
        )
        self.assertEqual(
            first_compiled["scenario_sha256"],
            second_compiled["scenario_sha256"],
        )
        self.assertNotEqual(
            first_compiled["request_sha256"],
            second_compiled["request_sha256"],
        )

    def test_switch_access_and_trunk_compile_without_vendor_semantics(self):
        request = request_fixture()
        request["nodes"].append(
            {
                "name": "sw1",
                "kind": "switch",
                "interfaces": [
                    {"name": "p1", "mode": "access", "access_vlan": 10},
                    {
                        "name": "p2",
                        "mode": "trunk",
                        "allowed_vlans": [20, 10, 20],
                        "native_vlan": 10,
                    },
                ],
            }
        )
        compiled = compile_network_sandbox_scenario(request).as_dict()
        switch = next(
            node
            for node in compiled["scenario"]["topology"]["nodes"]
            if node["name"] == "sw1"
        )
        self.assertEqual(
            switch["interfaces"],
            [
                {"name": "p1", "mode": "access", "access_vlan": 10},
                {
                    "name": "p2",
                    "mode": "trunk",
                    "native_vlan": 10,
                    "allowed_vlans": [10, 20],
                },
            ],
        )

    def test_unknown_vendor_or_firewall_semantics_are_not_invented(self):
        request = request_fixture()
        request["nodes"][1]["firewall"] = [{"action": "allow"}]
        with self.assertRaisesRegex(
            NetworkSandboxScenarioCompileError,
            "unsupported fields",
        ):
            compile_network_sandbox_scenario(request)

    def test_interface_cannot_be_linked_twice(self):
        request = request_fixture()
        request["links"].append(
            {
                "name": "duplicate-client-link",
                "endpoints": ["client:eth0", "internet:service0"],
            }
        )
        with self.assertRaisesRegex(
            NetworkSandboxScenarioCompileError,
            "linked more than once",
        ):
            compile_network_sandbox_scenario(request)

    def test_unknown_link_endpoint_fails_closed(self):
        request = request_fixture()
        request["links"][0]["endpoints"][1] = "edge:does-not-exist"
        with self.assertRaisesRegex(
            NetworkSandboxScenarioCompileError,
            "unknown endpoint",
        ):
            compile_network_sandbox_scenario(request)

    def test_switch_cannot_be_flow_source(self):
        request = request_fixture()
        request["nodes"].append(
            {
                "name": "sw1",
                "kind": "switch",
                "interfaces": [{"name": "p1", "mode": "access", "access_vlan": 10}],
            }
        )
        request["tests"][0]["src_node"] = "sw1"
        with self.assertRaisesRegex(
            NetworkSandboxScenarioCompileError,
            "cannot be a switch",
        ):
            compile_network_sandbox_scenario(request)

    def test_unsupported_protocol_fails_closed(self):
        request = request_fixture()
        request["tests"][0]["protocol"] = "gre"
        with self.assertRaisesRegex(
            NetworkSandboxScenarioCompileError,
            "protocol must be one of",
        ):
            compile_network_sandbox_scenario(request)

    def test_physical_or_production_promotion_is_rejected(self):
        compiled = compile_network_sandbox_scenario(request_fixture()).as_dict()

        physical = copy.deepcopy(compiled)
        physical["hardware_verified"] = True
        with self.assertRaisesRegex(
            NetworkSandboxScenarioCompileError,
            "hardware_verified=false",
        ):
            validate_compiled_network_sandbox_scenario(physical)

        production = copy.deepcopy(compiled)
        production["production_write_authorized"] = True
        with self.assertRaisesRegex(
            NetworkSandboxScenarioCompileError,
            "production_write_authorized=false",
        ):
            validate_compiled_network_sandbox_scenario(production)

    def test_scenario_tamper_breaks_digest(self):
        compiled = compile_network_sandbox_scenario(request_fixture()).as_dict()
        tampered = copy.deepcopy(compiled)
        tampered["scenario"]["tests"][0]["expect"] = "blocked"
        with self.assertRaisesRegex(
            NetworkSandboxScenarioCompileError,
            "scenario SHA-256 mismatch",
        ):
            validate_compiled_network_sandbox_scenario(tampered)

    def test_compiled_record_tamper_breaks_digest(self):
        compiled = compile_network_sandbox_scenario(request_fixture()).as_dict()
        tampered = copy.deepcopy(compiled)
        tampered["scenario_id"] = "other-scenario"
        with self.assertRaisesRegex(
            NetworkSandboxScenarioCompileError,
            "compiled record SHA-256 mismatch",
        ):
            validate_compiled_network_sandbox_scenario(tampered)


if __name__ == "__main__":
    unittest.main()
