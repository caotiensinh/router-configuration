import json
import unittest
from pathlib import Path

from router_configuration.routeros_discovery import normalize_routeros_snapshot
from router_configuration.routeros_evidence import build_routeros_discovery_evidence
from router_configuration.routeros_generation import generate_routeros_plan
from router_configuration.routeros_wireguard_renderer import PRIVATE_KEY_PLACEHOLDER
from router_configuration.safe_subset_ir import SafeSubsetCompiler


ROOT = Path(__file__).resolve().parents[1]
PROFILE = ROOT / "examples" / "rd-10g-1g" / "deployment-profile.json"
RAW = ROOT / "tests" / "fixtures" / "routeros_readonly_snapshot.json"
PUBLIC_KEY_A = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="


def profile():
    return json.loads(PROFILE.read_text(encoding="utf-8"))


def explicit_wireguard_profile():
    data = profile()
    data["intent"]["vpn"]["wireguard"] = {
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
            }
        ],
    }
    return data


def evidence():
    raw = json.loads(RAW.read_text(encoding="utf-8"))
    return build_routeros_discovery_evidence(normalize_routeros_snapshot(raw))


class RouterOSWireGuardGenerationTests(unittest.TestCase):
    def test_explicit_wireguard_attaches_only_deferred_templates(self):
        data = explicit_wireguard_profile()
        ir = SafeSubsetCompiler().compile(data).as_dict()
        result = generate_routeros_plan(profile=data, ir=ir, evidence=evidence())
        self.assertTrue(result.ok, result.errors)
        plan = result.as_dict()["render_plan"]
        self.assertIsNotNone(plan)
        self.assertFalse(plan["complete"])
        self.assertFalse(plan["secrets_resolved"])
        self.assertFalse(plan["transport_present"])
        self.assertFalse(plan["apply_available"])
        self.assertFalse(plan["write_authorized"])

        normal_ids = [item["command_id"] for item in plan["commands"]]
        self.assertTrue(all(not value.startswith("wireguard.") for value in normal_ids))
        normal_source = "\n".join(item["command"] for item in plan["commands"])
        self.assertNotIn(PRIVATE_KEY_PLACEHOLDER, normal_source)
        self.assertNotIn("/interface/wireguard", normal_source)

        extension = plan["deferred_generation_extensions"]["wireguard"]
        self.assertEqual(extension["schema_version"], "routeros-wireguard-template-plan/1")
        self.assertEqual(extension["source"], "explicit_operator_facts_unresolved_secret")
        self.assertEqual(extension["interface_name"], "wg-enterprise")
        self.assertEqual(extension["listen_port"], 51820)
        self.assertFalse(extension["secrets_resolved"])
        self.assertFalse(extension["transport_present"])
        self.assertFalse(extension["apply_available"])
        self.assertFalse(extension["write_authorized"])

        binding = extension["secret_bindings"][PRIVATE_KEY_PLACEHOLDER]
        self.assertEqual(binding["reference"], "vault://routers/rd-router-01/wireguard-private-key")
        self.assertFalse(binding["resolved"])
        templates = "\n".join(item["template"] for item in extension["command_templates"])
        self.assertIn(PRIVATE_KEY_PLACEHOLDER, templates)
        self.assertNotIn("vault://", templates)

    def test_wireguard_blocker_is_retained_and_narrowed_to_secret_and_transaction_boundary(self):
        data = explicit_wireguard_profile()
        ir = SafeSubsetCompiler().compile(data).as_dict()
        plan = generate_routeros_plan(profile=data, ir=ir, evidence=evidence()).as_dict()["render_plan"]
        self.assertIsNotNone(plan)
        blockers = {
            item["operation_id"]: item
            for item in plan["blocked_operations"]
        }
        self.assertIn("vpn.wireguard", blockers)
        blocker = blockers["vpn.wireguard"]
        self.assertEqual(
            blocker["required_inputs"],
            ["wireguard.private_key_secret_binding", "transaction.authorized_apply_boundary"],
        )
        self.assertIn("intentionally unavailable", blocker["reason"])
        self.assertIn("routing.multiwan.capacity_weighted", blockers)
        self.assertIn("security.baseline", blockers)
        self.assertNotIn("qos.policy", blockers)
        qos = plan["generation_extensions"]["qos"]
        self.assertEqual(qos["policy"], "latency_sensitive_first")
        self.assertFalse(qos["default_traffic_marked"])

    def test_incomplete_reference_wireguard_remains_original_blocker_without_templates(self):
        data = profile()
        ir = SafeSubsetCompiler().compile(data).as_dict()
        plan = generate_routeros_plan(profile=data, ir=ir, evidence=evidence()).as_dict()["render_plan"]
        self.assertIsNotNone(plan)
        self.assertNotIn("deferred_generation_extensions", plan)
        blocker = next(item for item in plan["blocked_operations"] if item["operation_id"] == "vpn.wireguard")
        self.assertIn("wireguard.addresses", blocker["required_inputs"])
        self.assertIn("wireguard.listen_port", blocker["required_inputs"])
        self.assertIn("wireguard.peers", blocker["required_inputs"])
        self.assertIn("qos", plan["generation_extensions"])

    def test_deferred_wireguard_generation_is_deterministic(self):
        data = explicit_wireguard_profile()
        ir = SafeSubsetCompiler().compile(data).as_dict()
        first = generate_routeros_plan(profile=data, ir=ir, evidence=evidence()).as_dict()["render_plan"]
        second = generate_routeros_plan(profile=data, ir=ir, evidence=evidence()).as_dict()["render_plan"]
        self.assertEqual(first, second)


if __name__ == "__main__":
    unittest.main()
