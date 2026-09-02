import copy
import json
import unittest
from pathlib import Path

from router_configuration.render_readiness import assess_render_readiness
from router_configuration.routeros_discovery import normalize_routeros_snapshot
from router_configuration.routeros_evidence import build_routeros_discovery_evidence
from router_configuration.safe_subset_ir import SafeSubsetCompiler


ROOT = Path(__file__).resolve().parents[1]
PROFILE_PATH = ROOT / "examples" / "rd-10g-1g" / "deployment-profile.json"
RAW_FIXTURE = ROOT / "tests" / "fixtures" / "routeros_readonly_snapshot.json"


def profile():
    return json.loads(PROFILE_PATH.read_text(encoding="utf-8"))


def evidence():
    raw = json.loads(RAW_FIXTURE.read_text(encoding="utf-8"))
    return build_routeros_discovery_evidence(normalize_routeros_snapshot(raw))


class RenderReadinessTests(unittest.TestCase):
    def test_valid_inputs_are_only_ready_for_generation_not_write(self):
        p = profile()
        ir = SafeSubsetCompiler().compile(p).as_dict()
        result = assess_render_readiness(profile=p, ir=ir, evidence=evidence())
        self.assertTrue(result.ok, result.errors)
        payload = result.as_dict()
        self.assertEqual(payload["claim"], "ready_for_renderer_generation")
        self.assertFalse(payload["renderer_enabled"])
        self.assertFalse(payload["write_authorized"])

    def test_tampered_ir_is_blocked(self):
        p = profile()
        ir = SafeSubsetCompiler().compile(p).as_dict()
        ir["operations"][0]["attributes"]["capacity_mbps"] = 999999
        result = assess_render_readiness(profile=p, ir=ir, evidence=evidence())
        self.assertFalse(result.ok)
        self.assertTrue(any("IR operations" in item or "digest" in item for item in result.errors))

    def test_tampered_evidence_is_blocked(self):
        p = profile()
        ir = SafeSubsetCompiler().compile(p).as_dict()
        ev = evidence()
        ev["normalized_state"]["interfaces"][0]["running"] = False
        result = assess_render_readiness(profile=p, ir=ir, evidence=ev)
        self.assertFalse(result.ok)
        self.assertTrue(any("evidence:" in item for item in result.errors))

    def test_missing_required_capability_is_blocked(self):
        p = profile()
        ir = SafeSubsetCompiler().compile(p).as_dict()
        ev = evidence()
        state = copy.deepcopy(ev["normalized_state"])
        state["missing_surfaces"] = ["wireguard_peers"]
        ev = build_routeros_discovery_evidence(state)
        result = assess_render_readiness(profile=p, ir=ir, evidence=ev)
        self.assertFalse(result.ok)
        self.assertTrue(any("wireguard" in item.lower() for item in result.errors))

    def test_management_path_is_mandatory_for_high_risk_intents(self):
        p = profile()
        p["recovery_access"]["documented"] = False
        # compile first from an otherwise valid profile, then demonstrate readiness rejects it.
        p_for_ir = profile()
        ir = SafeSubsetCompiler().compile(p_for_ir).as_dict()
        result = assess_render_readiness(profile=p, ir=ir, evidence=evidence())
        self.assertFalse(result.ok)
        self.assertTrue(any("management" in item.lower() or "recovery" in item.lower() for item in result.errors))


if __name__ == "__main__":
    unittest.main()
