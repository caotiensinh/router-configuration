import copy
import importlib.util
import json
import unittest
from pathlib import Path

from router_configuration.routeros_evidence import build_routeros_discovery_evidence


ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "lab" / "chr" / "evaluate_technical_acceptance.py"
GOLDEN = ROOT / "tests" / "fixtures" / "routeros_normalized_golden.json"
COMMENT = "routercfg-disposable-live-acceptance"

spec = importlib.util.spec_from_file_location("evaluate_technical_acceptance", SCRIPT)
module = importlib.util.module_from_spec(spec)
assert spec and spec.loader
spec.loader.exec_module(module)


class CHRTechnicalAcceptanceTests(unittest.TestCase):
    def _evidence(self):
        state = copy.deepcopy(json.loads(GOLDEN.read_text(encoding="utf-8")))
        state["firewall"]["filter"][0]["comment"] = COMMENT
        state["firewall"]["nat"][0]["comment"] = COMMENT
        state["wireguard"]["interfaces"][0]["comment"] = COMMENT
        state["qos"]["simple_queues"][0]["comment"] = COMMENT
        return build_routeros_discovery_evidence(state)

    def _bootstrap(self, evidence):
        return {
            "ok": True,
            "platform": {
                "version": evidence["platform"]["version"],
                "architecture": evidence["platform"]["architecture"],
            },
            "reader": {"username": "routercfg-reader", "policy": "read,rest-api"},
            "https": {"url": "https://127.0.0.1:9443", "certificate_verification": True},
            "production_writer_available": False,
        }

    def _machine(self, evidence):
        return {
            "schema_version": "routeros-ci-machine-provenance/1",
            "claim": "machine_observation_only",
            "operator_attested": False,
            "automatic_target_matrix_admission": False,
            "routeros_version": evidence["platform"]["version"],
            "normalized_state_sha256": evidence["state_sha256"],
        }

    def test_valid_populated_phase_only_authorizes_clean_read_only_run(self):
        evidence = self._evidence()
        result = module.evaluate(
            evidence=evidence,
            bootstrap=self._bootstrap(evidence),
            machine_provenance=self._machine(evidence),
        )
        self.assertTrue(result["ok"])
        self.assertEqual(result["phase"], "populated_validation")
        self.assertEqual(result["claim"], "ready_for_clean_read_only_admission_run")
        self.assertTrue(result["fixture_setup_writes_performed"])
        self.assertFalse(result["acceptance_collection_write_operations"])
        self.assertFalse(result["eligible_for_operator_attestation"])
        self.assertFalse(result["renderer_enabled"])
        self.assertFalse(result["write_authorized"])
        self.assertFalse(result["automatic_target_matrix_admission"])

    def test_reader_policy_mismatch_is_blocking(self):
        evidence = self._evidence()
        bootstrap = self._bootstrap(evidence)
        bootstrap["reader"]["policy"] = "read,write,rest-api"
        result = module.evaluate(
            evidence=evidence,
            bootstrap=bootstrap,
            machine_provenance=self._machine(evidence),
        )
        self.assertFalse(result["ok"])
        self.assertEqual(result["claim"], "populated_validation_failed")
        self.assertIn("secure bootstrap reader policy must be exactly read,rest-api", result["errors"])

    def test_machine_provenance_cannot_claim_operator_attestation(self):
        evidence = self._evidence()
        machine = self._machine(evidence)
        machine["operator_attested"] = True
        result = module.evaluate(
            evidence=evidence,
            bootstrap=self._bootstrap(evidence),
            machine_provenance=machine,
        )
        self.assertFalse(result["ok"])
        self.assertIn("machine provenance must not claim operator attestation", result["errors"])


if __name__ == "__main__":
    unittest.main()
