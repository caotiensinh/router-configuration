import copy
import importlib.util
import json
import unittest
from pathlib import Path

from router_configuration.routeros_evidence import build_routeros_discovery_evidence


ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "lab" / "chr" / "evaluate_clean_admission.py"
GOLDEN = ROOT / "tests" / "fixtures" / "routeros_normalized_golden.json"

spec = importlib.util.spec_from_file_location("evaluate_clean_admission", SCRIPT)
module = importlib.util.module_from_spec(spec)
assert spec and spec.loader
spec.loader.exec_module(module)


class CHRCleanAdmissionTests(unittest.TestCase):
    def _evidence(self):
        state = copy.deepcopy(json.loads(GOLDEN.read_text(encoding="utf-8")))
        for section in (state["firewall"]["filter"], state["firewall"]["nat"]):
            for item in section:
                item.pop("comment", None)
        for item in state["wireguard"]["interfaces"]:
            item.pop("comment", None)
        for item in state["qos"]["simple_queues"]:
            item.pop("comment", None)
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
            "https": {"certificate_verification": True},
            "production_writer_available": False,
        }

    def _machine(self, evidence):
        return {
            "schema_version": "routeros-ci-machine-provenance/1",
            "claim": "machine_observation_only",
            "operator_attested": False,
            "automatic_target_matrix_admission": False,
            "workflow_sha": "a" * 40,
            "routeros_version": evidence["platform"]["version"],
            "normalized_state_sha256": evidence["state_sha256"],
        }

    def _manifest(self):
        return {
            "schema_version": "routeros-clean-admission-execution/1",
            "phase": "clean_read_only_admission",
            "fresh_boot": True,
            "snapshot_mode": True,
            "fixture_population_performed": False,
            "acceptance_collection_write_operations_performed": False,
            "mutation_requests_attempted": False,
            "collection_http_methods": ["GET"],
            "prepared_context_setup_writes_preceded_phase": True,
            "workflow_sha": "a" * 40,
        }

    def test_clean_phase_is_ready_only_for_operator_attestation(self):
        evidence = self._evidence()
        result = module.evaluate_clean_admission(
            evidence=evidence,
            bootstrap=self._bootstrap(evidence),
            machine_provenance=self._machine(evidence),
            execution_manifest=self._manifest(),
        )
        self.assertTrue(result["ok"])
        self.assertEqual(result["claim"], "ready_for_operator_attestation")
        self.assertTrue(result["fixture_markers_absent"])
        self.assertTrue(result["reader_policy_verified"])
        self.assertTrue(result["eligible_for_operator_attestation"])
        self.assertFalse(result["automatic_target_matrix_admission"])
        self.assertFalse(result["renderer_enabled"])
        self.assertFalse(result["write_authorized"])

    def test_reader_policy_expansion_blocks_clean_admission(self):
        evidence = self._evidence()
        bootstrap = self._bootstrap(evidence)
        bootstrap["reader"]["effective_policy"].append("write")
        result = module.evaluate_clean_admission(
            evidence=evidence,
            bootstrap=bootstrap,
            machine_provenance=self._machine(evidence),
            execution_manifest=self._manifest(),
        )
        self.assertFalse(result["ok"])
        self.assertFalse(result["reader_policy_verified"])
        self.assertIn(
            "clean admission effective reader policy is not the exact approved set",
            result["errors"],
        )

    def test_declared_policy_mismatch_blocks_clean_admission(self):
        evidence = self._evidence()
        bootstrap = self._bootstrap(evidence)
        bootstrap["reader"]["policy"] = "read,rest-api"
        result = module.evaluate_clean_admission(
            evidence=evidence,
            bootstrap=bootstrap,
            machine_provenance=self._machine(evidence),
            execution_manifest=self._manifest(),
        )
        self.assertFalse(result["ok"])
        self.assertIn(
            "clean admission declared reader policy is not the exact approved set",
            result["errors"],
        )

    def test_population_marker_blocks_clean_admission(self):
        evidence = self._evidence()
        state = copy.deepcopy(evidence["normalized_state"])
        state["firewall"]["filter"][0]["comment"] = module.POPULATION_MARKER
        evidence = build_routeros_discovery_evidence(state)
        machine = self._machine(evidence)
        result = module.evaluate_clean_admission(
            evidence=evidence,
            bootstrap=self._bootstrap(evidence),
            machine_provenance=machine,
            execution_manifest=self._manifest(),
        )
        self.assertFalse(result["ok"])
        self.assertIn(
            "clean admission evidence contains populated-validation fixture objects",
            result["errors"],
        )

    def test_any_mutation_attempt_blocks_clean_admission(self):
        evidence = self._evidence()
        manifest = self._manifest()
        manifest["mutation_requests_attempted"] = True
        result = module.evaluate_clean_admission(
            evidence=evidence,
            bootstrap=self._bootstrap(evidence),
            machine_provenance=self._machine(evidence),
            execution_manifest=manifest,
        )
        self.assertFalse(result["ok"])
        self.assertIn("clean admission phase must not attempt mutation requests", result["errors"])

    def test_non_get_collection_method_blocks_clean_admission(self):
        evidence = self._evidence()
        manifest = self._manifest()
        manifest["collection_http_methods"] = ["GET", "PUT"]
        result = module.evaluate_clean_admission(
            evidence=evidence,
            bootstrap=self._bootstrap(evidence),
            machine_provenance=self._machine(evidence),
            execution_manifest=manifest,
        )
        self.assertFalse(result["ok"])
        self.assertIn("clean admission collection HTTP methods must be exactly ['GET']", result["errors"])


if __name__ == "__main__":
    unittest.main()
