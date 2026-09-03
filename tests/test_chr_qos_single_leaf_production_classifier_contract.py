import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
WORKFLOW = ROOT / ".github" / "workflows" / "chr-qos-single-leaf-diagnostic.yml"
HARNESS = ROOT / "lab" / "chr" / "run_qos_single_leaf_diagnostic.sh"
PROBE = ROOT / "lab" / "chr" / "diagnose_qos_single_leaf.py"


class CHRQoSSingleLeafProductionClassifierContractTests(unittest.TestCase):
    def test_workflow_runs_full_matrix_on_official_disposable_chr(self):
        source = WORKFLOW.read_text(encoding="utf-8")
        self.assertIn('CHR_VERSION: "7.24.1"', source)
        self.assertIn("DIAGNOSTIC_MODE: full", source)
        self.assertIn("production-forward classifier to global-leaf isolation matrix", source)
        self.assertIn("run_qos_single_leaf_diagnostic.sh", source)
        self.assertNotIn("DIAG_OVERRIDE", source)
        self.assertNotIn("192.168.11.", source)
        self.assertNotIn("ROUTEROS_PASSWORD", source)

    def test_probe_retains_production_ef_classifier_and_changes_only_leaf_parent(self):
        source = PROBE.read_text(encoding="utf-8")
        self.assertIn('mode == "ef"', source)
        self.assertIn('"production_mark_source_retained": mode == "ef"', source)
        self.assertIn('str(selected_rule.get("dscp") or "") != "46"', source)
        self.assertIn("parent=global", source)
        self.assertIn('"production_renderer_modified": False', source)
        self.assertIn('"production_packet_flow_acceptance": False', source)
        self.assertIn('"production_writer_available": False', source)

    def test_harness_uses_bounded_counter_visibility_and_tests_both_queue_kinds(self):
        source = HARNESS.read_text(encoding="utf-8")
        self.assertIn('COUNTER_SETTLE_ATTEMPTS="${COUNTER_SETTLE_ATTEMPTS:-20}"', source)
        self.assertIn('COUNTER_SETTLE_INTERVAL="${COUNTER_SETTLE_INTERVAL:-0.25}"', source)
        self.assertIn("mangle_delta > 0 and leaf_delta > 0", source)
        self.assertIn("run_phase ef default-small ef-default-small 46 44000", source)
        self.assertIn("run_phase ef routercfg-qos-fq ef-fq-codel 46 48000", source)
        self.assertIn("'production_packet_flow_acceptance': False", source)
        self.assertIn("'latency_performance_claimed': False", source)
        self.assertIn("'bandwidth_guarantee_claimed': False", source)


if __name__ == "__main__":
    unittest.main()
