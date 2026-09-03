import importlib.util
import sys
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "lab" / "chr" / "verify_transaction_recovery.py"
WORKFLOW = ROOT / ".github" / "workflows" / "chr-transaction-recovery.yml"


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
    def test_recovery_is_independent_and_advances_only_after_new_reads(self):
        module = load(SCRIPT, "verify_transaction_recovery_contract")
        self.assertTrue(hasattr(module, "verify_transaction_recovery"))
        source = SCRIPT.read_text(encoding="utf-8")
        admission_call = source.index("admission.verify_transaction_runtime_admission(")
        fresh_client = source.index("recovery_admin = base.LoopbackCHRAdmin(admin_url)")
        managed_absent = source.index("runtime_rollback._assert_managed_state_absent(recovery_admin)")
        recovery_snapshot = source.index("chunked._configuration_snapshot_with_pcc(recovery_admin)")
        transition = source.index('to_phase="rolled_back"')
        self.assertLess(admission_call, fresh_client)
        self.assertLess(fresh_client, managed_absent)
        self.assertLess(managed_absent, recovery_snapshot)
        self.assertLess(recovery_snapshot, transition)
        self.assertIn('"management_recovered": True', source)
        self.assertIn('"connectivity_recovered": True', source)
        self.assertIn('"managed_objects_reconciled": True', source)
        self.assertIn('"recovery_verification_claimed": True', source)
        self.assertIn('"independent_post_rollback_read": True', source)

    def test_recovery_keeps_production_write_boundary_closed(self):
        source = SCRIPT.read_text(encoding="utf-8")
        self.assertIn('"production_writer_available": False', source)
        self.assertIn('"transport_exposed_to_product": False', source)
        self.assertIn('"physical_router_targeted": False', source)
        self.assertIn('"production_allowed": False', source)
        self.assertIn('"write_authorized": False', source)
        self.assertIn('"operator_attestation_claimed": False', source)
        for forbidden in (
            "ROUTEROS_PASSWORD",
            "private_key",
            "requests.",
            "socket.",
            "subprocess",
            "paramiko",
        ):
            self.assertNotIn(forbidden, source)

    def test_workflow_is_disposable_chr_snapshot_and_sanitized(self):
        workflow = WORKFLOW.read_text(encoding="utf-8")
        self.assertIn('CHR_VERSION: "7.24.1"', workflow)
        self.assertIn("download.mikrotik.com/routeros/${CHR_VERSION}", workflow)
        self.assertIn("-snapshot", workflow)
        self.assertIn("127.0.0.1:9480", workflow)
        self.assertIn("verify_transaction_recovery.py", workflow)
        self.assertIn('--workflow-sha "$GITHUB_SHA"', workflow)
        self.assertIn('payload["recovery_verification_claimed"] is True', workflow)
        self.assertIn('payload["independent_post_rollback_read"] is True', workflow)
        self.assertIn('payload["lifecycle"]["phase"] == "rolled_back"', workflow)
        self.assertIn('payload["recovery"]["pre_state_digest_restored"] is True', workflow)
        self.assertNotIn("ROUTEROS_PASSWORD", workflow)


if __name__ == "__main__":
    unittest.main()
