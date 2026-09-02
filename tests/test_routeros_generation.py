import copy
import json
import unittest
from pathlib import Path

from router_configuration.routeros_discovery import normalize_routeros_snapshot
from router_configuration.routeros_evidence import build_routeros_discovery_evidence
from router_configuration.routeros_generation import generate_routeros_plan
from router_configuration.safe_subset_ir import SafeSubsetCompiler


ROOT = Path(__file__).resolve().parents[1]
PROFILE = ROOT / "examples" / "rd-10g-1g" / "deployment-profile.json"
RAW = ROOT / "tests" / "fixtures" / "routeros_readonly_snapshot.json"


def profile():
    return json.loads(PROFILE.read_text(encoding="utf-8"))


def explicit_pcc_profile():
    data = profile()
    data["topology"]["wans"] = [
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
                "failover_distance": 10,
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
                "failover_distance": 20,
                "health_probe_targets": ["9.9.9.9", "208.67.222.222"],
            },
        },
    ]
    return data


def add_explicit_firewall_facts(data):
    security = data["intent"]["security"]
    security["management_sources"] = ["192.168.11.0/24"]
    security["anti_spoofing"] = True
    security["icmp_policy"] = "essential_ipv4"
    security["required_wan_services"] = []
    return data


def explicit_firewall_profile():
    return add_explicit_firewall_facts(profile())


def explicit_pcc_and_firewall_profile():
    return add_explicit_firewall_facts(explicit_pcc_profile())


def ir(p=None):
    return SafeSubsetCompiler().compile(p or profile()).as_dict()


def evidence():
    raw = json.loads(RAW.read_text(encoding="utf-8"))
    return build_routeros_discovery_evidence(normalize_routeros_snapshot(raw))


def evidence_with_state_mutation(mutator):
    current = evidence()
    state = copy.deepcopy(current["normalized_state"])
    mutator(state)
    return build_routeros_discovery_evidence(state)


class RouterOSGenerationGateTests(unittest.TestCase):
    def test_verified_inputs_generate_only_a_non_applicable_artifact(self):
        p = profile()
        result = generate_routeros_plan(profile=p, ir=ir(p), evidence=evidence())
        self.assertTrue(result.ok, result.errors)
        payload = result.as_dict()
        self.assertEqual(payload["claim"], "routeros_generation_complete")
        self.assertFalse(payload["transport_present"])
        self.assertFalse(payload["apply_available"])
        self.assertFalse(payload["write_authorized"])
        plan = payload["render_plan"]
        self.assertIsNotNone(plan)
        self.assertEqual(plan["claim"], "generation_partial")
        self.assertFalse(plan["complete"])
        self.assertFalse(plan["secrets_resolved"])
        self.assertFalse(plan["apply_available"])
        self.assertFalse(plan["write_authorized"])
        self.assertTrue(
            any(
                item["operation_id"] == "routing.multiwan.capacity_weighted"
                for item in plan["blocked_operations"]
            )
        )
        self.assertTrue(
            any(
                item["operation_id"] == "security.baseline"
                for item in plan["blocked_operations"]
            )
        )
        self.assertNotIn("generation_extensions", plan)
        self.assertNotIn("state_bound_extensions", plan)

    def test_explicit_firewall_facts_replace_only_security_blocker(self):
        p = explicit_firewall_profile()
        result = generate_routeros_plan(profile=p, ir=ir(p), evidence=evidence())
        self.assertTrue(result.ok, result.errors)
        plan = result.as_dict()["render_plan"]
        self.assertIsNotNone(plan)
        self.assertFalse(plan["complete"])
        self.assertEqual(
            {item["operation_id"] for item in plan["blocked_operations"]},
            {"routing.multiwan.capacity_weighted", "vpn.wireguard", "qos.policy"},
        )
        self.assertFalse(
            any(item["operation_id"] == "security.baseline" for item in plan["blocked_operations"])
        )
        extension = plan["generation_extensions"]["enterprise_firewall"]
        self.assertEqual(extension["schema_version"], "routeros-firewall-command-plan/1")
        self.assertEqual(extension["policy"], "enterprise_baseline_ipv4_input_v0.1")
        self.assertEqual(extension["icmp_policy"], "essential_ipv4")
        self.assertEqual(extension["source"], "explicit_operator_facts")
        self.assertGreater(extension["command_count"], 0)
        self.assertFalse(extension["transport_present"])
        self.assertFalse(extension["apply_available"])
        self.assertFalse(extension["write_authorized"])

        command_ids = [item["command_id"] for item in plan["commands"]]
        firewall_start = command_ids.index("firewall.00.stage-guard")
        self.assertGreater(firewall_start, 0)
        self.assertEqual(command_ids[-1], "firewall.99.remove-stage-guard")
        command_text = "\n".join(item["command"] for item in plan["commands"])
        self.assertIn('jump-target="routercfg-input"', command_text)
        self.assertIn('jump-target="routercfg-icmp"', command_text)

    def test_explicit_paths_merge_chr_verified_pcc_after_base_commands(self):
        p = explicit_pcc_profile()
        result = generate_routeros_plan(profile=p, ir=ir(p), evidence=evidence())
        self.assertTrue(result.ok, result.errors)
        plan = result.as_dict()["render_plan"]
        self.assertIsNotNone(plan)
        self.assertFalse(plan["complete"])
        self.assertEqual(len(plan["commands"]), 38)
        self.assertFalse(
            any(
                item["operation_id"] == "routing.multiwan.capacity_weighted"
                for item in plan["blocked_operations"]
            )
        )
        self.assertEqual(
            {item["operation_id"] for item in plan["blocked_operations"]},
            {"security.baseline", "vpn.wireguard", "qos.policy"},
        )
        extension = plan["state_bound_extensions"]["capacity_weighted_pcc"]
        self.assertEqual(extension["command_count"], 21)
        self.assertEqual(extension["source"], "verified_normalized_state")
        self.assertEqual(len(extension["pcc_spec"]["buckets"]), 11)
        self.assertFalse(extension["transport_present"])
        self.assertFalse(extension["apply_available"])
        self.assertFalse(extension["write_authorized"])

        base_commands = plan["commands"][:17]
        pcc_commands = plan["commands"][17:]
        self.assertTrue(all(not item["command_id"].startswith("pcc.") for item in base_commands))
        self.assertTrue(all(item["command_id"].startswith("pcc.") for item in pcc_commands))
        self.assertEqual(
            [item["section"] for item in pcc_commands[:8]],
            ["pcc_policy_route"] * 8,
        )
        self.assertEqual(
            sum(item["section"] == "firewall_mangle" for item in pcc_commands),
            13,
        )

    def test_firewall_and_pcc_merge_without_losing_either_extension(self):
        p = explicit_pcc_and_firewall_profile()
        result = generate_routeros_plan(profile=p, ir=ir(p), evidence=evidence())
        self.assertTrue(result.ok, result.errors)
        plan = result.as_dict()["render_plan"]
        self.assertIsNotNone(plan)
        self.assertEqual(
            {item["operation_id"] for item in plan["blocked_operations"]},
            {"vpn.wireguard", "qos.policy"},
        )
        firewall = plan["generation_extensions"]["enterprise_firewall"]
        pcc = plan["state_bound_extensions"]["capacity_weighted_pcc"]
        self.assertGreater(firewall["command_count"], 0)
        self.assertEqual(pcc["command_count"], 21)

        command_ids = [item["command_id"] for item in plan["commands"]]
        firewall_end = command_ids.index("firewall.99.remove-stage-guard")
        pcc_start = next(index for index, value in enumerate(command_ids) if value.startswith("pcc."))
        self.assertLess(firewall_end, pcc_start)
        self.assertTrue(all(value.startswith("pcc.") for value in command_ids[pcc_start:]))
        self.assertFalse(plan["transport_present"])
        self.assertFalse(plan["apply_available"])
        self.assertFalse(plan["write_authorized"])

    def test_explicit_pcc_is_deterministic(self):
        p = explicit_pcc_profile()
        first = generate_routeros_plan(profile=p, ir=ir(p), evidence=evidence()).as_dict()
        second = generate_routeros_plan(profile=p, ir=ir(p), evidence=evidence()).as_dict()
        self.assertEqual(first["render_plan"], second["render_plan"])

    def test_explicit_firewall_is_deterministic(self):
        p = explicit_firewall_profile()
        first = generate_routeros_plan(profile=p, ir=ir(p), evidence=evidence()).as_dict()
        second = generate_routeros_plan(profile=p, ir=ir(p), evidence=evidence()).as_dict()
        self.assertEqual(first["render_plan"], second["render_plan"])

    def test_active_fasttrack_blocks_state_bound_generation(self):
        p = explicit_pcc_profile()

        def add_fasttrack(state):
            state["firewall"]["filter"].append(
                {
                    ".id": "*FT1",
                    "chain": "forward",
                    "action": "fasttrack-connection",
                    "disabled": False,
                }
            )

        result = generate_routeros_plan(
            profile=p,
            ir=ir(p),
            evidence=evidence_with_state_mutation(add_fasttrack),
        )
        self.assertFalse(result.ok)
        self.assertIsNone(result.render_plan)
        self.assertTrue(any("FastTrack" in error for error in result.errors))

    def test_active_dstnat_blocks_state_bound_generation(self):
        p = explicit_pcc_profile()

        def add_dstnat(state):
            state["firewall"]["nat"].append(
                {
                    ".id": "*DN1",
                    "chain": "dstnat",
                    "action": "dst-nat",
                    "disabled": False,
                }
            )

        result = generate_routeros_plan(
            profile=p,
            ir=ir(p),
            evidence=evidence_with_state_mutation(add_dstnat),
        )
        self.assertFalse(result.ok)
        self.assertIsNone(result.render_plan)
        self.assertTrue(any("dstnat" in error.lower() for error in result.errors))

    def test_tampered_evidence_blocks_before_generation(self):
        p = profile()
        ev = evidence()
        ev["normalized_state"]["interfaces"][0]["running"] = False
        result = generate_routeros_plan(profile=p, ir=ir(p), evidence=ev)
        self.assertFalse(result.ok)
        self.assertIsNone(result.render_plan)
        self.assertTrue(any("evidence:" in error for error in result.errors))

    def test_profile_ir_binding_is_mandatory(self):
        p = profile()
        changed = copy.deepcopy(p)
        changed["topology"]["wans"][0]["capacity_mbps"] = 9000
        result = generate_routeros_plan(profile=changed, ir=ir(p), evidence=evidence())
        self.assertFalse(result.ok)
        self.assertIsNone(result.render_plan)
        self.assertTrue(any("IR" in error for error in result.errors))

    def test_generation_boundary_source_has_no_transport_or_secret_resolution(self):
        source = (ROOT / "src" / "router_configuration" / "routeros_generation.py").read_text(
            encoding="utf-8"
        )
        for forbidden in (
            "urllib.request",
            "requests.",
            "http.client",
            "paramiko",
            "socket.",
            "subprocess",
            "ROUTEROS_PASSWORD",
            "vault.read",
            "keyring.get",
            "def apply(",
            "def execute(",
        ):
            self.assertNotIn(forbidden, source)


if __name__ == "__main__":
    unittest.main()
