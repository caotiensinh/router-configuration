import importlib.util
import sys
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "lab" / "chr" / "verify_transaction_post_apply.py"
WORKFLOW = ROOT / ".github" / "workflows" / "chr-transaction-post-apply-verification.yml"


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


class CHRTransactionPostApplyContractTests(unittest.TestCase):
    def test_success_path_uses_fresh_post_apply_reads_before_verified(self):
        module = load(SCRIPT, "verify_transaction_post_apply_contract")
        self.assertTrue(hasattr(module, "verify_transaction_post_apply"))
        source = SCRIPT.read_text(encoding="utf-8")
        apply_call = source.index("apply_result = runtime_rollback._execute_import(")
        fresh_client = source.index("verifier_admin = base.LoopbackCHRAdmin(admin_url)")
        interface_check = source.index("verified_interfaces = _required_interfaces_running(verifier_admin)")
        intended_state = source.index("verified_counts = runtime_rollback._assert_mutated_state(verifier_admin)")
        fresh_snapshot = source.index("verified_post_state = chunked._configuration_snapshot_with_pcc(verifier_admin)")
        pending = source.index('to_phase="verification_pending"')
        verified = source.index('to_phase="verified"')
        self.assertLess(apply_call, fresh_client)
        self.assertLess(fresh_client, interface_check)
        self.assertLess(interface_check, intended_state)
        self.assertLess(intended_state, fresh_snapshot)
        self.assertLess(fresh_snapshot, pending)
        self.assertLess(pending, verified)
        self.assertIn('"fresh_rest_session": True', source)
        self.assertIn('"apply_observation_reused_for_verification_state": False', source)
        self.assertIn('"post_apply_verification_claimed": True', source)
        self.assertIn('"management_survival_after_apply_claimed": True', source)
        self.assertIn('"management_survival_during_apply_claimed": False', source)
        self.assertIn('"routed_data_plane_claimed": False', source)

    def test_lab_cleanup_is_after_verification_and_does_not_change_lifecycle(self):
        source = SCRIPT.read_text(encoding="utf-8")
        verified = source.index('to_phase="verified"')
        cleanup = source.index("cleanup_result = runtime_rollback._execute_import(")
        self.assertLess(verified, cleanup)
        self.assertIn('"baseline_digest_restored": cleanup_sha256 == baseline_sha256', source)
        self.assertIn('"changes_transaction_lifecycle": False', source)

    def test_product_write_boundary_remains_closed(self):
        source = SCRIPT.read_text(encoding="utf-8")
        for marker in (
            '"production_writer_available": False',
            '"transport_exposed_to_product": False',
            '"physical_router_targeted": False',
            '"production_allowed": False',
            '"write_authorized": False',
            '"operator_attestation_claimed": False',
        ):
            self.assertIn(marker, source)

    def test_workflow_uses_official_disposable_chr_and_sanitized_evidence(self):
        workflow = WORKFLOW.read_text(encoding="utf-8")
        self.assertIn('CHR_VERSION: "7.24.1"', workflow)
        self.assertIn("actions/cache/restore@v4", workflow)
        self.assertIn("download.mikrotik.com/routeros/${CHR_VERSION}", workflow)
        self.assertIn("-snapshot", workflow)
        self.assertIn("127.0.0.1:9580", workflow)
        self.assertIn("verify_transaction_post_apply.py", workflow)
        self.assertIn('--workflow-sha "$GITHUB_SHA"', workflow)
        self.assertIn('payload["post_apply_verification_claimed"] is True', workflow)
        self.assertIn('payload["lifecycle"]["phase"] == "verified"', workflow)
        self.assertIn('payload["lab_cleanup"]["baseline_digest_restored"] is True', workflow)
        self.assertIn('payload["management_survival_during_apply_claimed"] is False', workflow)
        self.assertIn('payload["routed_data_plane_claimed"] is False', workflow)
        self.assertNotIn("ROUTEROS_PASSWORD", workflow)


if __name__ == "__main__":
    unittest.main()
