import json
import unittest
from pathlib import Path

from router_configuration.routeros_renderer import RouterOSSafeSubsetRenderer
from router_configuration.safe_subset_ir import SafeSubsetCompiler


ROOT = Path(__file__).resolve().parents[1]
PROFILE_PATH = ROOT / "examples" / "rd-10g-1g" / "deployment-profile.json"


def explicit_failover_profile():
    profile = json.loads(PROFILE_PATH.read_text(encoding="utf-8"))
    profile["topology"]["wans"] = [
        {
            "name": "wan10g",
            "interface": "sfp-sfpplus1",
            "capacity_mbps": 10000,
            "addressing": "static",
            "address": "192.0.2.2/30",
            "enabled": True,
            "routing": {
                "gateway": "192.0.2.1",
                "table": "to-wan10g",
                "failover_distance": 20,
                "health_probe_targets": ["1.1.1.1", "8.8.8.8"],
            },
        },
        {
            "name": "wan1g",
            "interface": "ether1",
            "capacity_mbps": 1000,
            "addressing": "static",
            "address": "198.51.100.2/30",
            "enabled": True,
            "routing": {
                "gateway": "198.51.100.1",
                "table": "to-wan1g",
                "failover_distance": 10,
                "health_probe_targets": ["9.9.9.9", "208.67.222.222"],
            },
        },
    ]
    return profile


class RouterOSRecursiveFailoverRendererTests(unittest.TestCase):
    def render(self):
        ir = SafeSubsetCompiler().compile(explicit_failover_profile()).as_dict()
        return RouterOSSafeSubsetRenderer().render(ir).as_dict()

    def test_explicit_static_dualwan_renders_recursive_health_routes(self):
        plan = self.render()
        sections = [item["section"] for item in plan["commands"]]
        self.assertEqual(len(plan["commands"]), 17)
        self.assertEqual(sections.count("ip_address"), 2)
        self.assertEqual(sections.count("routing_table"), 2)
        self.assertEqual(sections.count("ip_route"), 8)

        route_text = "\n".join(
            item["command"] for item in plan["commands"] if item["section"] == "ip_route"
        )
        self.assertIn('dst-address="1.1.1.1/32" gateway="192.0.2.1"', route_text)
        self.assertIn('dst-address="9.9.9.9/32" gateway="198.51.100.1"', route_text)
        self.assertIn("scope=10", route_text)
        self.assertIn("target-scope=11", route_text)
        self.assertIn("check-gateway=ping", route_text)

    def test_operator_distance_controls_priority_not_link_capacity(self):
        plan = self.render()
        commands = {
            item["command_id"]: item["command"]
            for item in plan["commands"]
            if item["section"] == "ip_route"
        }
        wan10g = next(
            command for command_id, command in commands.items()
            if command_id.startswith("route.20.default.020.wan10g")
        )
        wan1g = next(
            command for command_id, command in commands.items()
            if command_id.startswith("route.20.default.010.wan1g")
        )
        self.assertIn("distance=20", wan10g)
        self.assertIn("distance=10", wan1g)

    def test_pcc_remains_explicitly_blocked_after_failover_render(self):
        plan = self.render()
        blocked = {item["operation_id"]: item for item in plan["blocked_operations"]}
        routing = blocked["routing.multiwan.capacity_weighted"]
        self.assertIn("PCC", routing["reason"])
        self.assertEqual(routing["required_inputs"], [])
        self.assertFalse(plan["transport_present"])
        self.assertFalse(plan["apply_available"])
        self.assertFalse(plan["write_authorized"])


if __name__ == "__main__":
    unittest.main()
