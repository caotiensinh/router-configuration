import importlib.util
import sys
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "lab" / "chr" / "verify_transaction_recovery.py"
WORKFLOW = ROOT / ".github" / "workflows" / "chr-transaction-recovery-verification.yml"


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


class CHRTransactionRecoveryContractTests(unittest.TestCase):
    def test_recovery_verification_happens_after_admitted_runtime_returns(self):
        source = SCRIPT.read_text(encoding="utf-8")
        runtime = source.index("admission.verify_transaction_runtime_admission(")
        fresh_read = source.index("recovery_admin = base.LoopbackCHRAdmin(admin_url)")
        self.assertLess(runtime, fresh_read)
        self.assertIn("runtime_rollback._assert_managed_state_absent(recovery_admin)", source)
        self.assertIn("chunked._configuration_snapshot_with_pcc(recovery_admin)", source)
        self.assertIn("recovered_sha256 != baseline_sha256", source)
        self.assertIn('to_phase="rolled_back"', source)
        self.assertIn('"recovery_verification_claimed"] = True', source)
        self.assertIn('"post_apply_verification_claimed"] = False', source)
        self.assertIn('"management_survival_during_apply_claimed"] = False', source)
        self.assertIn('"production_writer_available"] = False', source)
        self.assertIn('"transport_exposed_to_product"] = False', source)
        self.assertIn('"write_authorized"] = False', source)

    def test_recovery_wrapper_does_not_add_direct_mutation_transport(self):
        source = SCRIPT.read_text(encoding="utf-8")
        for forbidden in (
            "ROUTEROS_PASSWORD",
            "private_key",
            "requests.",
            "socket.",
            "subprocess",
            'request("POST"',
            "paramiko",
        ):
            self.assertNotIn(forbidden, source)

    def test_workflow_is_official_disposable_chr_snapshot_only(self):
        workflow = WORKFLOW.read_text(encoding="utf-8")
        self.assertIn("CHR_VERSION: \"7.24.1\"", workflow)
        self.assertIn("download.mikrotik.com/routeros/${CHR_VERSION}", workflow)
        self.assertIn("-snapshot", workflow)
        self.assertIn("127.0.0.1:9480", workflow)
        self.assertIn("verify_transaction_recovery.py", workflow)
        self.assertIn('--workflow-sha "$GITHUB_SHA"', workflow)
        self.assertIn("recovery_verification_claimed", workflow)
        self.assertIn('payload["lifecycle"]["phase"] == "rolled_back"', workflow)
        self.assertIn("runtime_result_reused_for_recovery_state", workflow)
        self.assertIn("rollback_digest_matches_pre_state", workflow)
        self.assertIn("post_apply_verification_claimed", workflow)
        self.assertIn("binary_payload_present", workflow)
        self.assertNotIn("ROUTEROS_PASSWORD", workflow)

    def test_module_imports_without_runtime_io(self):
        module = load(SCRIPT, "verify_transaction_recovery_contract")
        self.assertTrue(callable(module.verify_transaction_recovery))
        self.assertTrue(issubclass(module.CHRTransactionRecoveryVerificationError, RuntimeError))


if __name__ == "__main__":
    unittest.main()
