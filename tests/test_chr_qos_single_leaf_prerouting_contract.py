import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
PROBE = ROOT / "lab" / "chr" / "diagnose_qos_single_leaf_prerouting.py"
HARNESS = ROOT / "lab" / "chr" / "run_qos_single_leaf_diagnostic.sh"
WORKFLOW = ROOT / ".github" / "workflows" / "chr-qos-single-leaf-prerouting-diagnostic.yml"


class CHRQoSSingleLeafPreroutingContractTests(unittest.TestCase):
    def test_probe_moves_only_default_lab_mark_to_prerouting(self):
        source = PROBE.read_text(encoding="utf-8")
        self.assertIn('PREROUTING_INGRESS = "ether3"', source)
        self.assertIn("chain=prerouting", source)
        self.assertIn("in-interface={flat._quote(PREROUTING_INGRESS)}", source)
        self.assertIn("packet-mark=no-mark action=mark-packet", source)
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

    def test_harness_has_bounded_prerouting_mode_without_removing_full_diagnostic(self):
        source = HARNESS.read_text(encoding="utf-8")
        self.assertIn('DIAGNOSTIC_MODE="${DIAGNOSTIC_MODE:-full}"', source)
        self.assertIn('DIAG="${DIAG_OVERRIDE:-${ROOT}/lab/chr/diagnose_qos_single_leaf.py}"', source)
        self.assertIn('"${DIAGNOSTIC_MODE}" == "prerouting-default-only"', source)
        self.assertIn("run_phase default default-small prerouting-default-small 0 42000", source)
        self.assertIn("run_phase default default-small default-default-small 0 42000", source)
        self.assertIn("run_phase ef default-small ef-default-small 46 44000", source)

    def test_workflow_is_official_disposable_chr_and_selects_only_timing_probe(self):
        if not WORKFLOW.exists():
            self.skipTest("prerouting timing workflow wiring commit not present yet")
        source = WORKFLOW.read_text(encoding="utf-8")
        self.assertIn('CHR_VERSION: "7.24.1"', source)
        self.assertIn("DIAGNOSTIC_MODE: prerouting-default-only", source)
        self.assertIn("diagnose_qos_single_leaf_prerouting.py", source)
        self.assertIn("run_qos_single_leaf_diagnostic.sh", source)
        self.assertIn("chr-qos-single-leaf-prerouting-${{ github.sha }}", source)
        self.assertNotIn("192.168.11.", source)
        self.assertNotIn("ROUTEROS_PASSWORD", source)
        artifact_section = source.split("name: Preserve sanitized prerouting timing evidence", 1)[1]
        self.assertNotIn(".img", artifact_section)
        self.assertNotIn("serial.log", artifact_section)


if __name__ == "__main__":
    unittest.main()
