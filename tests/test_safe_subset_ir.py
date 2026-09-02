import copy
import json
import unittest
from pathlib import Path

from router_configuration.safe_subset_ir import SafeSubsetCompiler


ROOT = Path(__file__).resolve().parents[1]
PROFILE_PATH = ROOT / "examples" / "rd-10g-1g" / "deployment-profile.json"


def load_profile():
    return json.loads(PROFILE_PATH.read_text(encoding="utf-8"))


def with_explicit_static_routing():
    profile = load_profile()
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
                "failover_distance": 1,
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
                "failover_distance": 2,
                "health_probe_targets": ["9.9.9.9", "208.67.222.222"],
            },
        },
    ]
    return profile


def with_explicit_firewall_facts():
    profile = load_profile()
    profile["intent"]["security"].update(
        {
            "management_sources": ["192.0.2.16/28"],
            "required_wan_services": [],
            "anti_spoofing": True,
            "icmp_policy": "essential_ipv4",
        }
    )
    return profile


class SafeSubsetIRTests(unittest.TestCase):
    def test_reference_profile_compiles_without_vendor_commands_or_write_transport(self):
        payload = SafeSubsetCompiler().compile(load_profile()).as_dict()
        self.assertEqual(payload["schema_version"], "config-safe-subset-ir/1")
        self.assertFalse(payload["vendor_commands_present"])
        self.assertFalse(payload["write_transport_present"])
        rendered = json.dumps(payload, sort_keys=True)
        self.assertNotIn("/ip route", rendered)
        self.assertNotIn("POST", rendered)
        self.assertNotIn("PUT", rendered)
        self.assertNotIn("PATCH", rendered)
        self.assertNotIn("DELETE", rendered)

    def test_capacity_weighting_is_ten_to_one(self):
        payload = SafeSubsetCompiler().compile(load_profile()).as_dict()
        operation = next(
            item
            for item in payload["operations"]
            if item["operation_id"] == "routing.multiwan.capacity_weighted"
        )
        self.assertEqual(operation["attributes"]["weights"], {"wan10g": 10, "wan1g": 1})

    def test_explicit_routing_facts_are_preserved_vendor_neutrally(self):
        payload = SafeSubsetCompiler().compile(with_explicit_static_routing()).as_dict()
        operation = next(
            item
            for item in payload["operations"]
            if item["operation_id"] == "routing.multiwan.capacity_weighted"
        )
        paths = operation["attributes"]["paths"]
        self.assertEqual(paths["wan10g"]["gateway"], "192.0.2.1")
        self.assertEqual(paths["wan10g"]["table"], "to-wan10g")
        self.assertEqual(paths["wan10g"]["address"], "192.0.2.2/30")
        self.assertEqual(paths["wan10g"]["failover_distance"], 1)
        self.assertEqual(paths["wan10g"]["health_probe_targets"], ["1.1.1.1", "8.8.8.8"])
        self.assertEqual(paths["wan1g"]["gateway"], "198.51.100.1")
        self.assertEqual(paths["wan1g"]["failover_distance"], 2)
        self.assertEqual(operation["attributes"]["weights"], {"wan10g": 10, "wan1g": 1})
        rendered = json.dumps(operation, sort_keys=True)
        self.assertNotIn("/ip/route", rendered)
        self.assertNotIn("/routing/table", rendered)

    def test_reference_profile_without_operator_routing_facts_does_not_invent_paths(self):
        payload = SafeSubsetCompiler().compile(load_profile()).as_dict()
        operation = next(
            item
            for item in payload["operations"]
            if item["operation_id"] == "routing.multiwan.capacity_weighted"
        )
        self.assertNotIn("paths", operation["attributes"])

    def test_reference_profile_without_firewall_facts_does_not_invent_management_sources(self):
        payload = SafeSubsetCompiler().compile(load_profile()).as_dict()
        operation = next(
            item for item in payload["operations"] if item["operation_id"] == "security.baseline"
        )
        self.assertNotIn("management_sources", operation["attributes"])
        self.assertNotIn("required_wan_services", operation["attributes"])
        self.assertNotIn("anti_spoofing", operation["attributes"])
        self.assertNotIn("icmp_policy", operation["attributes"])

    def test_explicit_firewall_facts_are_preserved_vendor_neutrally(self):
        payload = SafeSubsetCompiler().compile(with_explicit_firewall_facts()).as_dict()
        operation = next(
            item for item in payload["operations"] if item["operation_id"] == "security.baseline"
        )
        self.assertEqual(operation["attributes"]["management_sources"], ["192.0.2.16/28"])
        self.assertEqual(operation["attributes"]["required_wan_services"], [])
        self.assertTrue(operation["attributes"]["anti_spoofing"])
        self.assertEqual(operation["attributes"]["icmp_policy"], "essential_ipv4")
        rendered = json.dumps(operation, sort_keys=True)
        self.assertNotIn("/ip/firewall", rendered)
        self.assertNotIn("action=", rendered)

    def test_firewall_management_source_must_be_bounded(self):
        profile = with_explicit_firewall_facts()
        profile["intent"]["security"]["management_sources"] = ["0.0.0.0/0"]
        with self.assertRaisesRegex(ValueError, "entire address space"):
            SafeSubsetCompiler().compile(profile)

    def test_required_wan_service_sources_must_be_bounded_when_declared(self):
        profile = with_explicit_firewall_facts()
        profile["intent"]["security"]["required_wan_services"] = [
            {
                "name": "example-service",
                "protocol": "udp",
                "dst_port": 51820,
                "source_cidrs": ["0.0.0.0/0"],
            }
        ]
        with self.assertRaisesRegex(ValueError, "bounded IPv4 CIDRs"):
            SafeSubsetCompiler().compile(profile)

    def test_enterprise_firewall_refuses_disabled_anti_spoofing(self):
        profile = with_explicit_firewall_facts()
        profile["intent"]["security"]["anti_spoofing"] = False
        with self.assertRaisesRegex(ValueError, "anti_spoofing"):
            SafeSubsetCompiler().compile(profile)

    def test_digest_and_operation_order_are_deterministic(self):
        compiler = SafeSubsetCompiler()
        first = compiler.compile(load_profile()).as_dict()
        second = compiler.compile(load_profile()).as_dict()
        self.assertEqual(first, second)
        ids = [item["operation_id"] for item in first["operations"]]
        self.assertEqual(ids, sorted(ids))

    def test_wireguard_secret_remains_reference_only(self):
        payload = SafeSubsetCompiler().compile(load_profile()).as_dict()
        operation = next(
            item for item in payload["operations"] if item["operation_id"] == "vpn.wireguard"
        )
        self.assertEqual(
            operation["secret_references"],
            ["vault://routers/rd-router-01/wireguard"],
        )
        self.assertNotIn("secret_ref", operation["attributes"])

    def test_management_from_wan_is_refused(self):
        profile = load_profile()
        profile["intent"]["security"]["management_from_wan"] = True
        with self.assertRaisesRegex(ValueError, "management_from_wan"):
            SafeSubsetCompiler().compile(profile)

    def test_plaintext_wireguard_secret_is_refused(self):
        profile = load_profile()
        profile["intent"]["vpn"]["wireguard"]["secret_ref"] = "plaintext-secret"
        with self.assertRaises(ValueError):
            SafeSubsetCompiler().compile(profile)

    def test_input_profile_is_not_mutated(self):
        profile = load_profile()
        original = copy.deepcopy(profile)
        SafeSubsetCompiler().compile(profile)
        self.assertEqual(profile, original)


if __name__ == "__main__":
    unittest.main()
