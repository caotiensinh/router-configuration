import importlib.util
import sys
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "lab" / "chr" / "verify_transaction_management_during_apply.py"
WORKFLOW = ROOT / ".github" / "workflows" / "chr-transaction-management-during-apply.yml"


def load(path: Path, name: str):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    assert spec and spec.loader
    sys.path.insert(0, str(path.parent))
    try:
        spec.loader.exec_module(module)
    finally:
        sys.path.pop(0)
    return module


class CHRTransactionManagementDuringApplyContractTests(unittest.TestCase):
    def test_source_preserves_exact_order_and_probes_every_step(self):
        source = SCRIPT.read_text(encoding="utf-8")
        self.assertIn("for step_index, command in enumerate(commands, start=1):", source)
        self.assertIn('"mode": "ordered_single_command_chunks"', source)
        self.assertIn('"exact_generated_order_preserved": True', source)
        self.assertIn('"probe_after_every_mutation_step": True', source)
        self.assertIn('"expected_in_progress_probe_count": command_count - 1', source)
        self.assertIn('"management_survival_during_apply_claimed": True', source)
        self.assertIn('"continuous_in_command_monitoring_claimed": False', source)

        execute_pos = source.index("step_result = runtime_rollback._execute_import(")
        probe_pos = source.index("management_probes.append(", execute_pos)
        self.assertLess(execute_pos, probe_pos)

    def test_management_probe_requires_fresh_rest_and_running_interfaces(self):
        module = load(SCRIPT, "verify_transaction_management_during_apply_contract")
        source = SCRIPT.read_text(encoding="utf-8")
        self.assertIn("probe_admin = base.LoopbackCHRAdmin(admin_url)", source)
        self.assertIn("probe_admin.assert_disposable_chr()", source)
        self.assertIn("post_apply._required_interfaces_running(probe_admin)", source)
        self.assertTrue(hasattr(module, "_management_probe"))

    def test_source_admits_before_first_mutation_and_restores_baseline(self):
        source = SCRIPT.read_text(encoding="utf-8")
        admission_pos = source.index("admit_disposable_chr_candidate(")
        mutation_pos = source.index("step_result = runtime_rollback._execute_import(")
        self.assertLess(admission_pos, mutation_pos)
        self.assertIn("validate_transaction_backup_evidence(", source)
        self.assertIn("cleanup_sha256 == baseline_sha256", source)
        self.assertIn("runtime_rollback._assert_managed_state_absent(admin)", source)
        self.assertIn('"physical_router_targeted": False', source)
        self.assertIn('"production": False', source)
        self.assertIn('"production_writer_available": False', source)
        self.assertIn('"write_authorized": False', source)

    def test_source_does_not_embed_product_credentials_or_generic_writer(self):
        source = SCRIPT.read_text(encoding="utf-8")
        for forbidden in (
            "ROUTEROS_PASSWORD",
            "private_key",
            "requests.",
            "socket.",
            "paramiko",
        ):
            self.assertNotIn(forbidden, source)

    def test_workflow_uses_official_disposable_chr_and_sanitized_contract(self):
        workflow = WORKFLOW.read_text(encoding="utf-8")
        self.assertIn('CHR_VERSION: "7.24.1"', workflow)
        self.assertIn("download.mikrotik.com/routeros/${CHR_VERSION}", workflow)
        self.assertIn("-snapshot", workflow)
        self.assertIn("127.0.0.1:9680", workflow)
        self.assertIn("verify_transaction_management_during_apply.py", workflow)
        self.assertIn('--workflow-sha "$GITHUB_SHA"', workflow)
        self.assertIn('management_survival_during_apply_claimed', workflow)
        self.assertIn('continuous_in_command_monitoring_claimed', workflow)
        self.assertIn('in_progress_probe_count', workflow)
        self.assertNotIn("ROUTEROS_PASSWORD", workflow)


if __name__ == "__main__":
    unittest.main()
