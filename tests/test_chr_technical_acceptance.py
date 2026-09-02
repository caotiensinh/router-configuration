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
            "reader": {
                "username": "routercfg-reader",
                "policy": "read,api,rest-api",
                "effective_policy": ["api", "read", "rest-api"],
            },
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

    def test_valid_populated_phase_records_technical_validation_only(self):
        evidence = self._evidence()
        result = module.evaluate(
            evidence=evidence,
            bootstrap=self._bootstrap(evidence),
            machine_provenance=self._machine(evidence),
        )
        self.assertTrue(result["ok"], result["errors"])
        self.assertEqual(result["phase"], "populated_validation")
        self.assertEqual(result["claim"], "populated_surface_validation_passed")
        self.assertTrue(result["reader_policy_verified"])
        self.assertTrue(result["fixture_setup_writes_performed"])
        self.assertFalse(result["acceptance_collection_write_operations"])
        self.assertFalse(result["eligible_for_operator_attestation"])
        self.assertFalse(result["renderer_enabled"])
        self.assertFalse(result["write_authorized"])
        self.assertFalse(result["automatic_target_matrix_admission"])

    def test_declared_reader_privilege_expansion_is_blocking(self):
        evidence = self._evidence()
        bootstrap = self._bootstrap(evidence)
        bootstrap["reader"]["policy"] = "read,api,rest-api,write"
        result = module.evaluate(
            evidence=evidence,
            bootstrap=bootstrap,
            machine_provenance=self._machine(evidence),
        )
        self.assertFalse(result["ok"])
        self.assertIn(
            "secure bootstrap declared reader policy must be exactly read,api,rest-api",
            result["errors"],
        )

    def test_effective_reader_privilege_expansion_is_blocking(self):
        evidence = self._evidence()
        bootstrap = self._bootstrap(evidence)
        bootstrap["reader"]["effective_policy"].append("write")
        result = module.evaluate(
            evidence=evidence,
            bootstrap=bootstrap,
            machine_provenance=self._machine(evidence),
        )
        self.assertFalse(result["ok"])
        self.assertIn(
            "secure bootstrap effective reader policy must be exactly read,api,rest-api",
            result["errors"],
        )

    def test_effective_policy_must_be_recorded(self):
        evidence = self._evidence()
        bootstrap = self._bootstrap(evidence)
        bootstrap["reader"].pop("effective_policy")
        result = module.evaluate(
            evidence=evidence,
            bootstrap=bootstrap,
            machine_provenance=self._machine(evidence),
        )
        self.assertFalse(result["ok"])
        self.assertIn(
            "secure bootstrap reader effective_policy must be recorded from RouterOS",
            result["errors"],
        )

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
