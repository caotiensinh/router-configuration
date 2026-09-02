import copy
import importlib.util
import json
import unittest
from pathlib import Path

from router_configuration.routeros_evidence import build_routeros_discovery_evidence


ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "lab" / "chr" / "verify_populated_evidence.py"
GOLDEN = ROOT / "tests" / "fixtures" / "routeros_normalized_golden.json"
COMMENT = "routercfg-disposable-live-acceptance"

spec = importlib.util.spec_from_file_location("verify_populated_evidence", SCRIPT)
module = importlib.util.module_from_spec(spec)
assert spec and spec.loader
spec.loader.exec_module(module)


class CHRPopulatedEvidenceTests(unittest.TestCase):
    def _evidence(self):
        state = json.loads(GOLDEN.read_text(encoding="utf-8"))
        state = copy.deepcopy(state)
        state["firewall"]["filter"][0]["comment"] = COMMENT
        state["firewall"]["nat"][0]["comment"] = COMMENT
        state["wireguard"]["interfaces"][0]["comment"] = COMMENT
        state["qos"]["simple_queues"][0]["comment"] = COMMENT
        return build_routeros_discovery_evidence(state)

    def test_populated_surfaces_and_secret_boundary_pass(self):
        result = module.verify_populated_evidence(self._evidence())
        self.assertTrue(result["ok"])
        self.assertTrue(result["secret_boundary_verified"])
        self.assertEqual(
            result["populated_counts"],
            {
                "firewall_filter": 1,
                "firewall_nat": 1,
                "wireguard_interfaces": 1,
                "qos_simple_queues": 1,
            },
        )

    def test_missing_named_surface_is_blocking(self):
        evidence = self._evidence()
        evidence["normalized_state"]["qos"]["simple_queues"][0]["comment"] = "other"
        evidence = build_routeros_discovery_evidence(evidence["normalized_state"])
        result = module.verify_populated_evidence(evidence)
        self.assertFalse(result["ok"])
        self.assertIn(
            "expected populated acceptance object missing: qos_simple_queues",
            result["errors"],
        )

    def test_tampered_evidence_is_blocking(self):
        evidence = self._evidence()
        evidence["state_sha256"] = "0" * 64
        result = module.verify_populated_evidence(evidence)
        self.assertFalse(result["ok"])


if __name__ == "__main__":
    unittest.main()
