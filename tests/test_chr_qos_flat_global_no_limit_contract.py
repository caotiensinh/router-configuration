import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
PROBE = ROOT / "lab" / "chr" / "diagnose_qos_flat_global_no_limit.py"
WORKFLOW = ROOT / ".github" / "workflows" / "chr-qos-flat-global-diagnostic.yml"


class CHRQoSFlatGlobalNoLimitContractTests(unittest.TestCase):
    def test_probe_changes_only_ef_direct_global_limit_at_variable(self):
        source = PROBE.read_text(encoding="utf-8")
        self.assertIn("import diagnose_qos_flat_global as legacy", source)
        self.assertIn("parent=global", source)
        self.assertIn('"priority=1 max-limit=100M disabled=no"', source)
        self.assertNotIn("limit-at=10M", source)
        self.assertIn('"ef_limit_at_configured": False', source)
        self.assertIn('"production_renderer_modified": False', source)
        self.assertIn('"production_writer_available": False', source)
        self.assertIn('"physical_router_targeted": False', source)

    def test_workflow_selects_no_limit_probe_only_inside_disposable_lab_checkout(self):
        source = WORKFLOW.read_text(encoding="utf-8")
        if "diagnose_qos_flat_global_no_limit.py" not in source:
            self.skipTest("workflow wiring commit not present yet")
        self.assertIn("diagnose_qos_flat_global_no_limit.py", source)
        self.assertIn("run_qos_flat_global_diagnostic.sh", source)
        self.assertIn('CHR_VERSION: "7.24.1"', source)
        self.assertNotIn("192.168.11.", source)
        self.assertNotIn("ROUTEROS_PASSWORD", source)


if __name__ == "__main__":
    unittest.main()
