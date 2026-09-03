import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
WORKFLOW = ROOT / ".github" / "workflows" / "chr-qos-single-leaf-diagnostic.yml"
HARNESS = ROOT / "lab" / "chr" / "run_qos_single_leaf_diagnostic.sh"
PROBE = ROOT / "lab" / "chr" / "diagnose_qos_single_leaf.py"


class CHRQoSSingleLeafProductionClassifierContractTests(unittest.TestCase):
    def test_workflow_runs_production_global_matrix_on_official_disposable_chr(self):
        source = WORKFLOW.read_text(encoding="utf-8")
        self.assertIn('CHR_VERSION: "7.24.1"', source)
        self.assertIn("DIAGNOSTIC_MODE: production-global", source)
        self.assertIn("unmarked-default and production-EF global-leaf matrix", source)
        self.assertIn("run_qos_single_leaf_diagnostic.sh", source)
        self.assertNotIn("DIAG_OVERRIDE", source)
        self.assertNotIn("192.168.11.", source)
        self.assertNotIn("ROUTEROS_PASSWORD", source)

    def test_probe_supports_no_mark_without_default_mangle(self):
        source = PROBE.read_text(encoding="utf-8")
        self.assertIn('SUPPORTED_MODES = {"default", "no-mark", "ef"}', source)
        self.assertIn('mark = "no-mark"', source)
        self.assertIn("packet-mark=no-mark queue=", source)
        self.assertIn('"mangle_counter_required": mode != "no-mark"', source)
        self.assertIn('"default_mangle_present": bool(default_rules)', source)
        self.assertIn("no-mark mode unexpectedly created a default mangle rule", source)
        self.assertIn('str(production_ef.get("chain") or "") != "forward"', source)
        self.assertIn('str(production_ef.get("dscp") or "") != "46"', source)

    def test_probe_retains_production_ef_classifier_and_changes_only_leaf_parent(self):
        source = PROBE.read_text(encoding="utf-8")
        self.assertIn('mode in {"no-mark", "ef"}', source)
        self.assertIn("parent=global", source)
        self.assertIn('"production_renderer_modified": False', source)
        self.assertIn('"production_packet_flow_acceptance": False', source)
        self.assertIn('"production_writer_available": False', source)

    def test_harness_keeps_fail_closed_counters_and_tests_no_mark_plus_ef(self):
        source = HARNESS.read_text(encoding="utf-8")
        self.assertIn('COUNTER_SETTLE_ATTEMPTS="${COUNTER_SETTLE_ATTEMPTS:-20}"', source)
        self.assertIn('COUNTER_SETTLE_INTERVAL="${COUNTER_SETTLE_INTERVAL:-0.25}"', source)
        self.assertIn("mangle_required = bool(before.get('mangle_counter_required', True))", source)
        self.assertIn("visible = leaf_delta > 0 and (not mangle_required or mangle_delta > 0)", source)
        self.assertIn("'acceptance_relaxed': False", source)
        self.assertIn('if [[ "${DIAGNOSTIC_MODE}" == "production-global" ]]', source)
        self.assertIn("run_phase no-mark default-small no-mark-default-small 0 42000", source)
        self.assertIn("run_phase ef default-small ef-default-small 46 44000", source)
        self.assertIn("run_phase no-mark routercfg-qos-fq no-mark-fq-codel 0 46000", source)
        self.assertIn("run_phase ef routercfg-qos-fq ef-fq-codel 46 48000", source)
        self.assertIn("'default_mangle_required': False", source)
        self.assertIn("'production_packet_flow_acceptance': False", source)
        self.assertIn("'latency_performance_claimed': False", source)
        self.assertIn("'bandwidth_guarantee_claimed': False", source)


if __name__ == "__main__":
    unittest.main()
