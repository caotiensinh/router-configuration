import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
PROBE = ROOT / "lab" / "chr" / "diagnose_qos_flat_global_lab_ef_mark.py"
WORKFLOW = ROOT / ".github" / "workflows" / "chr-qos-flat-global-diagnostic.yml"


class CHRQoSFlatGlobalLabEFMarkContractTests(unittest.TestCase):
    def test_probe_changes_only_ef_mark_source_inside_disposable_lab(self):
        source = PROBE.read_text(encoding="utf-8")
        self.assertIn("import diagnose_qos_flat_global as legacy", source)
        self.assertIn('LAB_EF_MARK = "routercfg-qos-flat-ef-lab"', source)
        self.assertIn("dscp=46 packet-mark=no-mark action=mark-packet", source)
        self.assertIn("priority=1 limit-at=10M max-limit=100M disabled=no", source)
        self.assertIn("priority=8 max-limit=100M disabled=no", source)
        self.assertIn('"production_ef_rule_replaced_in_disposable_lab": True', source)
        self.assertIn('"production_renderer_modified": False', source)
        self.assertIn('"production_writer_available": False', source)
        self.assertIn('"physical_router_targeted": False', source)

    def test_probe_reuses_legacy_counter_and_evaluation_paths(self):
        source = PROBE.read_text(encoding="utf-8")
        self.assertIn("legacy.install = install", source)
        self.assertIn("legacy.cleanup = cleanup", source)
        self.assertIn("return legacy.main()", source)
        self.assertNotIn("def counters(", source)
        self.assertNotIn("def evaluate(", source)

    def test_workflow_selects_lab_ef_mark_probe_on_official_disposable_chr(self):
        source = WORKFLOW.read_text(encoding="utf-8")
        if "diagnose_qos_flat_global_lab_ef_mark.py" not in source:
            self.skipTest("lab-EF-mark experiment is not the active diagnostic")
        self.assertIn("diagnose_qos_flat_global_lab_ef_mark.py", source)
        self.assertIn("run_qos_flat_global_diagnostic.sh", source)
        self.assertIn('CHR_VERSION: "7.24.1"', source)
        self.assertNotIn("192.168.11.", source)
        self.assertNotIn("ROUTEROS_PASSWORD", source)


if __name__ == "__main__":
    unittest.main()
