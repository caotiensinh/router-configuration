import importlib.util
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "lab" / "chr" / "build_clean_execution_manifest.py"

spec = importlib.util.spec_from_file_location("build_clean_execution_manifest", SCRIPT)
module = importlib.util.module_from_spec(spec)
assert spec and spec.loader
spec.loader.exec_module(module)


class CHRCleanExecutionManifestTests(unittest.TestCase):
    def test_manifest_is_fixed_to_get_only_fresh_snapshot_phase(self):
        manifest = module.build_manifest("a" * 40)
        self.assertEqual(manifest["phase"], "clean_read_only_admission")
        self.assertTrue(manifest["fresh_boot"])
        self.assertTrue(manifest["snapshot_mode"])
        self.assertFalse(manifest["fixture_population_performed"])
        self.assertFalse(manifest["acceptance_collection_write_operations_performed"])
        self.assertFalse(manifest["mutation_requests_attempted"])
        self.assertEqual(manifest["collection_http_methods"], ["GET"])
        self.assertTrue(manifest["prepared_context_setup_writes_preceded_phase"])
        self.assertFalse(manifest["automatic_target_matrix_admission"])
        self.assertFalse(manifest["renderer_enabled"])
        self.assertFalse(manifest["write_authorized"])

    def test_invalid_workflow_sha_is_blocking(self):
        for value in ("", "abc", "g" * 40, "a" * 39, "a" * 41):
            with self.assertRaises(module.CleanManifestError):
                module.build_manifest(value)


if __name__ == "__main__":
    unittest.main()
