import copy
import json
import unittest
from pathlib import Path

from router_configuration.safe_subset_ir import SafeSubsetCompiler


ROOT = Path(__file__).resolve().parents[1]
PROFILE_PATH = ROOT / "examples" / "rd-10g-1g" / "deployment-profile.json"


def load_profile():
    return json.loads(PROFILE_PATH.read_text(encoding="utf-8"))


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
