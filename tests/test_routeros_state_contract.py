import copy
import json
import unittest
from pathlib import Path

from router_configuration.routeros_discovery import normalize_routeros_snapshot
from router_configuration.routeros_evidence import build_routeros_discovery_evidence
from router_configuration.routeros_state_contract import (
    routeros_state_digest,
    validate_routeros_state,
    verify_routeros_discovery_evidence,
)


FIXTURE = Path(__file__).parent / "fixtures" / "routeros_readonly_snapshot.json"


class RouterOSStateContractTests(unittest.TestCase):
    def setUp(self):
        raw = json.loads(FIXTURE.read_text(encoding="utf-8"))
        self.state = normalize_routeros_snapshot(raw)
        self.evidence = build_routeros_discovery_evidence(self.state)

    def test_normalized_fixture_satisfies_state_contract(self):
        result = validate_routeros_state(self.state)
        self.assertTrue(result.ok, result.errors)
        self.assertEqual(routeros_state_digest(self.state), self.evidence["state_sha256"])

    def test_unknown_state_field_is_rejected(self):
        tampered = dict(self.state)
        tampered["unexpected_writer_hint"] = {"command": "do-not-trust"}
        result = validate_routeros_state(tampered)
        self.assertFalse(result.ok)
        self.assertTrue(any("unknown top-level" in item for item in result.errors))

    def test_unredacted_secret_is_rejected(self):
        tampered = copy.deepcopy(self.state)
        tampered["wireguard"]["interfaces"][0]["private-key"] = "secret-material"
        result = validate_routeros_state(tampered)
        self.assertFalse(result.ok)
        self.assertTrue(any("unredacted" in item for item in result.errors))

    def test_evidence_verifier_detects_state_tampering(self):
        tampered = copy.deepcopy(self.evidence)
        tampered["normalized_state"]["interfaces"][0]["running"] = False
        result = verify_routeros_discovery_evidence(tampered)
        self.assertFalse(result.ok)
        self.assertIn("state_sha256 does not match normalized_state", result.errors)

    def test_evidence_verifier_detects_summary_tampering(self):
        tampered = copy.deepcopy(self.evidence)
        tampered["collection"]["record_counts"]["interfaces"] += 1
        tampered["capabilities"]["rest_read_supported"] = False
        result = verify_routeros_discovery_evidence(tampered)
        self.assertFalse(result.ok)
        self.assertIn(
            "collection.record_counts does not match normalized_state", result.errors
        )
        self.assertIn("capabilities do not match normalized_state assessment", result.errors)

    def test_generated_evidence_verifies_cleanly(self):
        result = verify_routeros_discovery_evidence(self.evidence)
        self.assertTrue(result.ok, result.errors)
        self.assertEqual(result.state["schema_version"], "routeros-state/1")


if __name__ == "__main__":
    unittest.main()
