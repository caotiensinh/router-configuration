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


def ir(p=None):
    return SafeSubsetCompiler().compile(p or profile()).as_dict()


def evidence():
    raw = json.loads(RAW.read_text(encoding="utf-8"))
    return build_routeros_discovery_evidence(normalize_routeros_snapshot(raw))


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
