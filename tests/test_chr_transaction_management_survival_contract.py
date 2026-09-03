import importlib.util
import sys
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "lab" / "chr" / "verify_transaction_management_survival.py"
WORKFLOW = ROOT / ".github" / "workflows" / "chr-transaction-management-survival.yml"


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


class CHRTransactionManagementSurvivalContractTests(unittest.TestCase):
    def test_observer_is_independent_and_spans_apply_window(self):
        module = load(SCRIPT, "verify_transaction_management_survival_contract")
        self.assertTrue(hasattr(module, "verify_transaction_management_survival"))
        source = SCRIPT.read_text(encoding="utf-8")
        observer_start = source.index("observer.start()")
        pre = source.index('observer.wait_for_successes("pre_apply"')
        begin = source.index("observer.begin_apply()")
        apply_call = source.index("apply_result = runtime_rollback._execute_import(")
        end = source.index("observer.end_apply()")
        post = source.index('observer.wait_for_successes("post_apply"')
        summary = source.index("management_summary = _summarize_management_samples")
        self.assertLess(observer_start, pre)
        self.assertLess(pre, begin)
        self.assertLess(begin, apply_call)
        self.assertLess(apply_call, end)
        self.assertLess(end, post)
        self.assertLess(post, summary)
        self.assertIn("self._admin = base.LoopbackCHRAdmin(admin_url)", source)
        self.assertIn('"independent_rest_session": True', source)
        self.assertIn('"management_survival_during_apply_claimed": True', source)

    def test_during_apply_requires_visible_mutation_and_zero_probe_failures(self):
        source = SCRIPT.read_text(encoding="utf-8")
        self.assertIn('item.get("phase") == "during_apply"', source)
        self.assertIn('int(item.get("managed_pcc_mangle_count") or 0) > 0', source)
        self.assertIn('"mutation_visible_during_apply": mutation_visible', source)
        self.assertIn('"all_probes_successful": not failures', source)
        self.assertIn("if failures:", source)
        self.assertIn("if not mutation_visible:", source)
        self.assertIn("if not management_running_all:", source)
        self.assertIn("_MIN_DURING_PROBES = 8", source)

    def test_lab_instrumentation_does_not_rewrite_rendered_commands(self):
        source = SCRIPT.read_text(encoding="utf-8")
        self.assertIn("def _instrumented_apply_script", source)
        self.assertIn("command = str(item[\"command\"])", source)
        self.assertIn("lines.append(command)", source)
        self.assertIn('"lab_only": True', source)
        self.assertIn('"rendered_commands_modified": False', source)
        self.assertIn('"rendered_command_order_modified": False', source)
        self.assertIn('"production_timing_claimed": False', source)

    def test_cleanup_and_product_write_boundary_remain_closed(self):
        source = SCRIPT.read_text(encoding="utf-8")
        self.assertIn('"baseline_digest_restored": cleanup_sha256 == baseline_sha256', source)
        self.assertIn('"changes_transaction_lifecycle": False', source)
        for marker in (
            '"production_writer_available": False',
            '"transport_exposed_to_product": False',
            '"physical_router_targeted": False',
            '"production_allowed": False',
            '"write_authorized": False',
            '"operator_attestation_claimed": False',
            '"routed_data_plane_claimed": False',
        ):
            self.assertIn(marker, source)

    def test_workflow_uses_official_disposable_chr_and_sanitized_evidence(self):
        workflow = WORKFLOW.read_text(encoding="utf-8")
        self.assertIn('CHR_VERSION: "7.24.1"', workflow)
        self.assertIn("actions/cache/restore@v4", workflow)
        self.assertIn("download.mikrotik.com/routeros/${CHR_VERSION}", workflow)
        self.assertIn("-snapshot", workflow)
        self.assertIn("127.0.0.1:9680", workflow)
        self.assertIn("verify_transaction_management_survival.py", workflow)
        self.assertIn('--workflow-sha "$GITHUB_SHA"', workflow)
        self.assertIn('payload["management_survival_during_apply_claimed"] is True', workflow)
        self.assertIn('survival["mutation_visible_during_apply"] is True', workflow)
        self.assertIn('survival["all_probes_successful"] is True', workflow)
        self.assertIn('payload["lab_cleanup"]["baseline_digest_restored"] is True', workflow)
        self.assertNotIn("ROUTEROS_PASSWORD", workflow)


if __name__ == "__main__":
    unittest.main()
