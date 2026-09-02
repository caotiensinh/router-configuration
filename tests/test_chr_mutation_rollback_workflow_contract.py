import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
WORKFLOW = ROOT / ".github" / "workflows" / "chr-mutation-rollback.yml"
SCRIPT = ROOT / "lab" / "chr" / "verify_mutation_rollback.py"


class CHRMutationRollbackWorkflowContractTests(unittest.TestCase):
    def test_workflow_is_disposable_loopback_snapshot_only(self):
        source = WORKFLOW.read_text(encoding="utf-8")
        self.assertIn("ci(chr-rollback):", source)
        self.assertIn("-snapshot", source)
        self.assertIn("127.0.0.1:9280", source)
        self.assertIn("verify_mutation_rollback.py", source)
        self.assertIn("chr-mutation-rollback-${{ github.sha }}", source)
        self.assertIn("actions/cache/restore@v4", source)
        self.assertIn("actions/cache/save@v4", source)
        self.assertIn('CHR_VERSION: "7.24.1"', source)
        self.assertNotIn("ROUTEROS_PASSWORD", source)
        self.assertNotIn("secrets.", source)

    def test_rollback_is_dry_run_proven_before_apply(self):
        source = SCRIPT.read_text(encoding="utf-8")
        dry_run = source.index("base._execute_import_dry_run")
        apply_import = source.index("file_name=APPLY_FILE")
        self.assertLess(dry_run, apply_import)
        self.assertIn("rollback_preflight", source)
        self.assertIn("configuration_rollback_sha256", source)
        self.assertIn("rollback_digest_restored", source)
        self.assertIn("managed_objects_removed", source)

    def test_failure_injection_precedes_rollback(self):
        source = SCRIPT.read_text(encoding="utf-8")
        failure = source.index("file_name=FAIL_FILE")
        rollback = source.index("file_name=ROLLBACK_FILE", failure)
        self.assertLess(failure, rollback)
        self.assertIn("expect_success=False", source[failure:rollback])


if __name__ == "__main__":
    unittest.main()
