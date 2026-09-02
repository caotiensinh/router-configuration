import importlib.util
import sys
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
CHR_DIR = ROOT / "lab" / "chr"
MATRIX = CHR_DIR / "diagnose_qos_mangle_matrix.py"
WORKFLOW = ROOT / ".github" / "workflows" / "chr-qos-diagnostic.yml"


def load_matrix():
    sys.path.insert(0, str(CHR_DIR))
    try:
        spec = importlib.util.spec_from_file_location("diagnose_qos_mangle_matrix_contract", MATRIX)
        module = importlib.util.module_from_spec(spec)
        assert spec and spec.loader
        spec.loader.exec_module(module)
        return module
    finally:
        sys.path.pop(0)


class CHRQoSMangleMatrixContractTests(unittest.TestCase):
    def test_matrix_changes_one_variable_per_probe(self):
        source = MATRIX.read_text(encoding="utf-8")
        for required in (
            '"exact_default"',
            '"alternate_mark_name"',
            '"dscp_zero"',
            '"without_packet_mark_match"',
            '"passthrough_yes"',
            '"current generated default classifier"',
            '"changes only the new packet-mark name"',
            '"changes only by adding a DSCP matcher"',
            '"changes only by removing packet-mark=no-mark matcher"',
            '"changes only passthrough false to true"',
        ):
            self.assertIn(required, source)

    def test_matrix_is_disposable_owned_and_cleans_each_rule(self):
        module = load_matrix()
        self.assertEqual(module.COMMENT_PREFIX, "routercfg:diag:qos:")
        source = MATRIX.read_text(encoding="utf-8")
        self.assertIn("_remove_by_comment(admin, comment)", source)
        self.assertIn('"temporary_rules_removed": True', source)
        self.assertIn('"physical_router_targeted": False', source)
        self.assertIn('"production_writer_available": False', source)
        self.assertIn('"write_authorized": False', source)
        for forbidden in (
            "ROUTEROS_PASSWORD",
            "ROUTEROS_USERNAME",
            "secrets.",
            "192.168.11.",
        ):
            self.assertNotIn(forbidden, source)

    def test_workflow_runs_matrix_before_reproducing_renderer_failure(self):
        source = WORKFLOW.read_text(encoding="utf-8")
        matrix = source.index("diagnose_qos_mangle_matrix.py")
        runtime = source.index("diagnose_qos_runtime.py")
        self.assertLess(matrix, runtime)
        self.assertIn("qos-mangle-matrix.json", source)
        self.assertIn("len(matrix.get('variants', [])) != 5", source)
        self.assertIn("chr-qos-diagnostic-${{ github.sha }}", source)


if __name__ == "__main__":
    unittest.main()
