import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
PROBE = ROOT / "lab" / "chr" / "diagnose_qos_flat_global_priority8.py"
WORKFLOW = ROOT / ".github" / "workflows" / "chr-qos-flat-global-diagnostic.yml"


class CHRQoSFlatGlobalPriority8ContractTests(unittest.TestCase):
    def test_probe_changes_only_ef_priority_variable(self):
        source = PROBE.read_text(encoding="utf-8")
        self.assertIn("import diagnose_qos_flat_global as legacy", source)
        self.assertIn('EF_DIAGNOSTIC_PRIORITY = 8', source)
        self.assertIn("priority=8 limit-at=10M max-limit=100M disabled=no", source)
        self.assertIn('"production_mark_source_retained": True', source)
        self.assertIn('"production_renderer_modified": False', source)
        self.assertIn('"production_writer_available": False', source)
        self.assertIn('"physical_router_targeted": False', source)
        self.assertNotIn("routercfg:lab:qos-flat:ef", source)

    def test_probe_reuses_legacy_counter_evaluation_and_cleanup(self):
        source = PROBE.read_text(encoding="utf-8")
        self.assertIn("legacy.install = install", source)
        self.assertIn("return legacy.main()", source)
        self.assertNotIn("def counters(", source)
        self.assertNotIn("def evaluate(", source)
        self.assertNotIn("def cleanup(", source)

    def test_workflow_selects_priority8_probe_on_official_disposable_chr(self):
        source = WORKFLOW.read_text(encoding="utf-8")
        if "diagnose_qos_flat_global_priority8.py" not in source:
            self.skipTest("priority8 experiment is not the active diagnostic")
        self.assertIn("diagnose_qos_flat_global_priority8.py", source)
        self.assertIn("run_qos_flat_global_diagnostic.sh", source)
        self.assertIn('CHR_VERSION: "7.24.1"', source)
        self.assertNotIn("192.168.11.", source)
        self.assertNotIn("ROUTEROS_PASSWORD", source)


if __name__ == "__main__":
    unittest.main()
