import json
import unittest
from pathlib import Path

from router_configuration.v1_extended_ir import compile_v1_extended_ir


ROOT = Path(__file__).resolve().parents[1]
PROFILE_PATH = ROOT / "examples" / "rd-10g-1g" / "deployment-profile.json"


def load_profile():
    return json.loads(PROFILE_PATH.read_text(encoding="utf-8"))


def add_vlan(profile):
    profile["intent"]["segmentation"] = {
        "enabled": True,
        "bridge": "br-lan",
        "vlans": [
            {"id": 20, "name": "users"},
            {"id": 99, "name": "management"},
        ],
        "ports": [
            {"interface": "ether5", "mode": "access", "access_vlan": 20},
            {
                "interface": "sfp-sfpplus2",
                "mode": "trunk",
                "allowed_vlans": [20, 99],
            },
        ],
        "management": {
            "vlan_id": 99,
            "port": "sfp-sfpplus2",
            "address": "10.99.0.1/24",
        },
    }


def add_pbr(profile):
    profile["intent"]["pbr"] = {
        "enabled": True,
        "strategy": "routing_rules",
        "rules": [
            {
                "name": "users-via-primary",
                "source_cidr": "10.20.0.0/24",
                "destination_cidr": "0.0.0.0/0",
                "table": "to-wan10g",
                "action": "lookup",
            }
        ],
    }


class V1ExtendedIRTests(unittest.TestCase):
    def test_vlan_intent_becomes_vendor_neutral_operation(self):
        profile = load_profile()
        add_vlan(profile)
        payload = compile_v1_extended_ir(profile).as_dict()
        operation = next(
            item for item in payload["operations"]
            if item["operation_id"] == "switching.vlan.segmentation"
        )
        self.assertEqual(operation["resource"], "vlan_segmentation_policy")
        self.assertEqual(operation["attributes"]["management"]["vlan_id"], 99)
        self.assertEqual(operation["attributes"]["management"]["address"], "10.99.0.1/24")
        rendered = json.dumps(operation, sort_keys=True)
        self.assertNotIn("/interface/bridge", rendered)
        self.assertNotIn("/interface/vlan", rendered)

    def test_pbr_intent_becomes_vendor_neutral_operation(self):
        profile = load_profile()
        add_pbr(profile)
        payload = compile_v1_extended_ir(profile).as_dict()
        operation = next(
            item for item in payload["operations"]
            if item["operation_id"] == "routing.pbr.rules"
        )
        self.assertEqual(operation["resource"], "policy_routing_rules")
        self.assertEqual(operation["attributes"]["strategy"], "routing_rules")
        self.assertEqual(operation["attributes"]["rules"][0]["source_cidr"], "10.20.0.0/24")
        rendered = json.dumps(operation, sort_keys=True)
        self.assertNotIn("/routing/rule", rendered)
        self.assertNotIn("action=", rendered)

    def test_vlan_and_pbr_extend_existing_operations_without_transport(self):
        profile = load_profile()
        add_vlan(profile)
        add_pbr(profile)
        payload = compile_v1_extended_ir(profile).as_dict()
        ids = [item["operation_id"] for item in payload["operations"]]
        self.assertEqual(ids, sorted(ids))
        self.assertIn("routing.multiwan.capacity_weighted", ids)
        self.assertIn("security.baseline", ids)
        self.assertIn("switching.vlan.segmentation", ids)
        self.assertIn("routing.pbr.rules", ids)
        self.assertFalse(payload["vendor_commands_present"])
        self.assertFalse(payload["write_transport_present"])

    def test_invalid_vlan_or_pbr_fails_closed(self):
        profile = load_profile()
        profile["intent"]["segmentation"] = {"enabled": True}
        with self.assertRaises(ValueError):
            compile_v1_extended_ir(profile)

        profile = load_profile()
        profile["intent"]["pbr"] = {
            "enabled": True,
            "strategy": "routing_rules",
            "rules": [],
        }
        with self.assertRaises(ValueError):
            compile_v1_extended_ir(profile)


if __name__ == "__main__":
    unittest.main()
