import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
PROBE = ROOT / "lab" / "chr" / "diagnose_qos_single_leaf_prerouting.py"
HARNESS = ROOT / "lab" / "chr" / "run_qos_single_leaf_diagnostic.sh"
WORKFLOW = ROOT / ".github" / "workflows" / "chr-qos-single-leaf-prerouting-diagnostic.yml"


class CHRQoSSingleLeafPreroutingContractTests(unittest.TestCase):
    def test_probe_moves_only_selected_lab_mark_to_prerouting(self):
        source = PROBE.read_text(encoding="utf-8")
        self.assertIn('PREROUTING_INGRESS = "ether3"', source)
        self.assertIn('mode not in {"default", "ef"}', source)
        self.assertIn("chain=prerouting", source)
        self.assertIn("in-interface={flat._quote(PREROUTING_INGRESS)}", source)
        self.assertIn("packet-mark=no-mark action=mark-packet", source)
        self.assertIn("dscp=46 packet-mark=no-mark", source)
        self.assertIn("parent=global", source)
        self.assertIn("queue=default-small", source)
        self.assertIn('"mark_chain": "prerouting"', source)
        self.assertIn('"sibling_leaf_present": False', source)
        self.assertNotIn("priority=1", source)
        self.assertNotIn("limit-at=10M", source)

    def test_probe_stays_diagnostic_only(self):
        source = PROBE.read_text(encoding="utf-8")
        self.assertIn('"production_renderer_modified": False', source)
        self.assertIn('"production_packet_flow_acceptance": False', source)
        self.assertIn('"production_writer_available": False', source)
        self.assertIn('"transport_exposed_to_product": False', source)
        self.assertIn('"write_authorized": False', source)
        self.assertIn('"physical_router_targeted": False', source)

    def test_harness_has_bounded_counter_visibility_without_relaxing_acceptance(self):
        source = HARNESS.read_text(encoding="utf-8")
        self.assertIn('DIAGNOSTIC_MODE="${DIAGNOSTIC_MODE:-full}"', source)
        self.assertIn('COUNTER_SETTLE_ATTEMPTS="${COUNTER_SETTLE_ATTEMPTS:-20}"', source)
        self.assertIn('COUNTER_SETTLE_INTERVAL="${COUNTER_SETTLE_INTERVAL:-0.25}"', source)
        self.assertIn("wait_for_counter_visibility()", source)
        self.assertIn("while (( attempt < COUNTER_SETTLE_ATTEMPTS )); do", source)
        self.assertIn("mangle_required = bool(before.get('mangle_counter_required', True))", source)
        self.assertIn("visible = leaf_delta > 0 and (not mangle_required or mangle_delta > 0)", source)
        self.assertIn("'acceptance_relaxed': False", source)
        self.assertIn("'counter_source': 'queue_tree_print_stats'", source)
        self.assertIn('DIAG="${DIAG_OVERRIDE:-${ROOT}/lab/chr/diagnose_qos_single_leaf.py}"', source)
        self.assertIn("run_phase default default-small default-default-small 0 42000", source)
        self.assertIn("run_phase ef default-small ef-default-small 46 44000", source)
        self.assertIn("run_phase default routercfg-qos-fq default-fq-codel 0 46000", source)
        self.assertIn("run_phase ef routercfg-qos-fq ef-fq-codel 46 48000", source)

    def test_workflow_is_official_disposable_chr_and_selects_full_timing_matrix(self):
        if not WORKFLOW.exists():
            self.skipTest("prerouting timing workflow wiring commit not present yet")
        source = WORKFLOW.read_text(encoding="utf-8")
        self.assertIn('CHR_VERSION: "7.24.1"', source)
        self.assertIn("DIAGNOSTIC_MODE: full", source)
        self.assertIn("diagnose_qos_single_leaf_prerouting.py", source)
        self.assertIn("run_qos_single_leaf_diagnostic.sh", source)
        self.assertIn("Run full prerouting mark-to-global-leaf timing matrix", source)
        self.assertIn("chr-qos-single-leaf-prerouting-${{ github.sha }}", source)
        self.assertNotIn("192.168.11.", source)
        self.assertNotIn("ROUTEROS_PASSWORD", source)
        artifact_section = source.split("name: Preserve sanitized prerouting timing evidence", 1)[1]
        self.assertNotIn(".img", artifact_section)
        self.assertNotIn("serial.log", artifact_section)


if __name__ == "__main__":
    unittest.main()
