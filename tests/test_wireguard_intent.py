import json
import unittest
from pathlib import Path

from router_configuration.safe_subset_ir import SafeSubsetCompiler
from router_configuration.wireguard_intent import WireGuardIntentError, normalize_wireguard_intent


ROOT = Path(__file__).resolve().parents[1]
PROFILE = ROOT / "examples" / "rd-10g-1g" / "deployment-profile.json"
PUBLIC_KEY_A = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="
PUBLIC_KEY_B = "AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE="


def profile():
    return json.loads(PROFILE.read_text(encoding="utf-8"))


def explicit_wireguard():
    return {
        "enabled": True,
        "secret_ref": "vault://routers/rd-router-01/wireguard-private-key",
        "name": "wg-enterprise",
        "addresses": ["10.250.0.1/24"],
        "listen_port": 51820,
        "mtu": 1420,
        "peers": [
            {
                "name": "branch-a",
                "public_key": PUBLIC_KEY_A,
                "tunnel_address": "10.250.0.2/32",
                "allowed_addresses": ["10.250.0.2/32", "10.40.0.0/24"],
                "routes": ["10.40.0.0/24"],
                "endpoint_address": "198.51.100.10",
                "endpoint_port": 51820,
                "persistent_keepalive": 25,
                "responder": False,
            },
            {
                "name": "branch-b",
                "public_key": PUBLIC_KEY_B,
                "tunnel_address": "10.250.0.3/32",
                "allowed_addresses": ["10.250.0.3/32", "10.50.0.0/24"],
                "routes": ["10.50.0.0/24"],
                "responder": True,
            },
        ],
    }


class WireGuardIntentTests(unittest.TestCase):
    def test_reference_profile_remains_incomplete_blocker_compatible(self):
        data = profile()
        payload = SafeSubsetCompiler().compile(data).as_dict()
        operation = next(item for item in payload["operations"] if item["operation_id"] == "vpn.wireguard")
        self.assertEqual(operation["attributes"], {"enabled": True})
        self.assertEqual(operation["secret_references"], ["vault://routers/rd-router-01/wireguard"])

    def test_explicit_wireguard_facts_compile_vendor_neutrally(self):
        data = profile()
        data["intent"]["vpn"]["wireguard"] = explicit_wireguard()
        payload = SafeSubsetCompiler().compile(data).as_dict()
        operation = next(item for item in payload["operations"] if item["operation_id"] == "vpn.wireguard")
        self.assertEqual(operation["attributes"]["name"], "wg-enterprise")
        self.assertEqual(operation["attributes"]["addresses"], ["10.250.0.1/24"])
        self.assertEqual(operation["attributes"]["listen_port"], 51820)
        self.assertEqual(operation["attributes"]["mtu"], 1420)
        self.assertEqual(len(operation["attributes"]["peers"]), 2)
        self.assertEqual(operation["secret_references"], ["vault://routers/rd-router-01/wireguard-private-key"])
        rendered = json.dumps(operation, sort_keys=True)
        self.assertNotIn("private_key", rendered)
        self.assertNotIn("private-key", rendered)
        self.assertNotIn("vault://", json.dumps(operation["attributes"], sort_keys=True))
        self.assertNotIn("/interface/wireguard", rendered)

    def test_partial_explicit_wireguard_facts_fail_closed(self):
        data = explicit_wireguard()
        data.pop("peers")
        with self.assertRaisesRegex(WireGuardIntentError, "incomplete"):
            normalize_wireguard_intent(data)

    def test_unbounded_allowed_address_fails_closed(self):
        data = explicit_wireguard()
        data["peers"][0]["allowed_addresses"].append("0.0.0.0/0")
        with self.assertRaisesRegex(WireGuardIntentError, "bounded IPv4 CIDR"):
            normalize_wireguard_intent(data)

    def test_overlapping_allowed_addresses_fail_closed(self):
        data = explicit_wireguard()
        data["peers"][1]["allowed_addresses"].append("10.40.0.128/25")
        with self.assertRaisesRegex(WireGuardIntentError, "overlap"):
            normalize_wireguard_intent(data)

    def test_plaintext_private_key_field_is_rejected_by_profile_validator_before_compile(self):
        data = profile()
        data["intent"]["vpn"]["wireguard"] = explicit_wireguard()
        data["intent"]["vpn"]["wireguard"]["private_key"] = "synthetic-but-forbidden"
        with self.assertRaisesRegex(ValueError, "profile must pass validation"):
            SafeSubsetCompiler().compile(data)


if __name__ == "__main__":
    unittest.main()
