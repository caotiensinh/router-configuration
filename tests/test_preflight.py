import json
import unittest
from pathlib import Path

from router_configuration.preflight import RouterOSPreflightEvaluator
from router_configuration.routeros_discovery import normalize_routeros_snapshot
from router_configuration.routeros_evidence import build_routeros_discovery_evidence


ROOT = Path(__file__).resolve().parents[1]
PROFILE = ROOT / "examples" / "rd-10g-1g" / "deployment-profile.json"
FIXTURE = Path(__file__).parent / "fixtures" / "routeros_readonly_snapshot.json"


class RouterOSPreflightTests(unittest.TestCase):
    def setUp(self):
        self.profile = json.loads(PROFILE.read_text(encoding="utf-8"))
        self.raw = json.loads(FIXTURE.read_text(encoding="utf-8"))

    def _evidence(self, raw=None):
        state = normalize_routeros_snapshot(raw or self.raw)
        return build_routeros_discovery_evidence(state)

    def test_reference_profile_passes_current_read_only_preflight_scope(self):
        result = RouterOSPreflightEvaluator().evaluate(self.profile, self._evidence())
        self.assertTrue(result.ok)
        self.assertEqual(result.blockers, ())
        self.assertTrue(all(finding.remediation for finding in result.findings))

    def test_missing_reference_port_is_blocking_with_remediation(self):
        raw = dict(self.raw)
        raw["interfaces"] = [
            item for item in self.raw["interfaces"] if item.get("name") != "ether1"
        ]
        result = RouterOSPreflightEvaluator().evaluate(self.profile, self._evidence(raw))
        self.assertFalse(result.ok)
        missing = [finding for finding in result.blockers if finding.code == "interface.missing"]
        self.assertTrue(missing)
        self.assertIn("physical port", missing[0].remediation)

    def test_model_mismatch_is_blocking(self):
        raw = dict(self.raw)
        raw["system_resource"] = dict(self.raw["system_resource"])
        raw["system_resource"]["board-name"] = "CCR2004-1G-12S+2XS"
        result = RouterOSPreflightEvaluator().evaluate(self.profile, self._evidence(raw))
        self.assertFalse(result.ok)
        self.assertIn("device.model_mismatch", {finding.code for finding in result.blockers})

    def test_requested_wireguard_requires_discovery_coverage(self):
        raw = dict(self.raw)
        raw.pop("wireguard_peers")
        result = RouterOSPreflightEvaluator().evaluate(self.profile, self._evidence(raw))
        self.assertFalse(result.ok)
        self.assertIn("wireguard.required", {finding.code for finding in result.blockers})


if __name__ == "__main__":
    unittest.main()
