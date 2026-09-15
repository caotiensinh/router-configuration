import importlib.util
import sys
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "lab" / "chr" / "verify_integrated_transaction_acceptance.py"
WORKFLOW = ROOT / ".github" / "workflows" / "chr-integrated-transaction-acceptance.yml"


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


class CHRIntegratedTransactionAcceptanceContractTests(unittest.TestCase):
    def test_single_transaction_orders_backup_apply_verify_failure_rollback_recovery(self):
        source = SCRIPT.read_text(encoding="utf-8")

        backup_pos = source.index(
            "backup_acceptance = real_backup.verify_transaction_backup_acceptance("
        )
        mutation_flag_pos = source.index("mutation_started = True")
        apply_pos = source.index(
            "apply_result = runtime_rollback._execute_import(", mutation_flag_pos
        )
        post_apply_pos = source.index(
            "post_apply_verification = _post_apply_checks(", apply_pos
        )
        failure_pos = source.index(
            "failure_result = runtime_rollback._execute_import(", post_apply_pos
        )
        rollback_pos = source.index(
            "rollback_result = runtime_rollback._execute_import(", failure_pos
        )
        recovery_pos = source.index(
            "recovery_admin = base.LoopbackCHRAdmin(admin_url)", rollback_pos
        )

        self.assertLess(backup_pos, mutation_flag_pos)
        self.assertLess(mutation_flag_pos, apply_pos)
        self.assertLess(apply_pos, post_apply_pos)
        self.assertLess(post_apply_pos, failure_pos)
        self.assertLess(failure_pos, rollback_pos)
        self.assertLess(rollback_pos, recovery_pos)

        self.assertIn('"single_transaction_binding": True', source)
        self.assertIn('"post_apply_verification_completed_before_failure": True', source)
        self.assertIn('"rollback_digest_matches_pre_state": True', source)
        self.assertIn('"management_rest_recovered": True', source)

    def test_lifecycle_stays_in_one_transaction_until_rolled_back(self):
        source = SCRIPT.read_text(encoding="utf-8")
        ordered = [
            'to_phase="authorized"',
            'to_phase="apply_observed"',
            'to_phase="verification_pending"',
            'to_phase="rollback_required"',
            'to_phase="rollback_observed"',
            'to_phase="rolled_back"',
        ]
        positions = [source.index(item) for item in ordered]
        self.assertEqual(positions, sorted(positions))
        self.assertNotIn('to_phase="verified"', source)

    def test_real_dual_backup_is_bound_before_first_mutation(self):
        source = SCRIPT.read_text(encoding="utf-8")
        self.assertIn(
            "real_backup.verify_transaction_backup_acceptance(", source
        )
        self.assertIn(
            '"production_backup_requirements_satisfied"', source
        )
        self.assertIn(
            '"protected_binary_sha256_from_downloaded_bytes": True', source
        )
        self.assertIn(
            'capture_proof.get("protected_binary_encryption_requested") != "aes-sha256"',
            source,
        )
        self.assertIn(
            'capture_proof.get("backup_password_persisted") is not False', source
        )
        self.assertIn(
            'capture_proof.get("fetch_password_persisted") is not False', source
        )
        self.assertIn(
            "validate_transaction_backup_evidence(", source
        )
        self.assertIn('"raw_binary_payload_present": False', source)

    def test_management_survival_and_fresh_post_apply_checks_are_required(self):
        source = SCRIPT.read_text(encoding="utf-8")
        self.assertIn("management._ManagementObserver(admin_url)", source)
        self.assertIn("management._instrumented_apply_script(commands)", source)
        self.assertIn("management._summarize_management_samples(", source)
        self.assertIn("observer.samples()", source)
        self.assertIn('"fresh_rest_session": True', source)
        self.assertIn('"all_applicable_checks_passed": True', source)
        self.assertIn('"wan": {', source)
        self.assertIn('"routing": {', source)

    def test_dns_verification_is_explicitly_applicability_gated(self):
        module = load(SCRIPT, "verify_integrated_transaction_acceptance_contract")
        source = SCRIPT.read_text(encoding="utf-8")
        self.assertTrue(hasattr(module, "_post_apply_checks"))
        self.assertIn('.lstrip().startswith("/ip/dns")', source)
        self.assertIn('"applicable": dns_applicable', source)
        self.assertIn('"not_applicable_reason": None', source)
        self.assertIn(
            'accepted 38-command transaction contains no /ip/dns mutation', source
        )

    def test_source_keeps_production_boundaries_closed(self):
        source = SCRIPT.read_text(encoding="utf-8")
        for required in (
            '"production_writer_available": False',
            '"transport_exposed_to_product": False',
            '"physical_router_targeted": False',
            '"production_allowed": False',
            '"write_authorized": False',
            '"routed_data_plane_claimed": False',
        ):
            self.assertIn(required, source)
        for forbidden in (
            "ROUTEROS_PASSWORD",
            "private_key",
            "requests.",
            "paramiko",
        ):
            self.assertNotIn(forbidden, source)

    def test_workflow_runs_official_snapshot_chr_with_rest_and_ssh(self):
        workflow = WORKFLOW.read_text(encoding="utf-8")
        self.assertIn('CHR_VERSION: "7.24.1"', workflow)
        self.assertIn("download.mikrotik.com/routeros/${CHR_VERSION}", workflow)
        self.assertIn("-snapshot", workflow)
        self.assertIn("hostfwd=tcp:127.0.0.1:9880-:80", workflow)
        self.assertIn("hostfwd=tcp:127.0.0.1:9823-:22", workflow)
        self.assertIn("openssh-client sshpass", workflow)
        self.assertIn("verify_integrated_transaction_acceptance.py", workflow)
        self.assertIn('--workflow-sha "$GITHUB_SHA"', workflow)
        self.assertIn("chr-integrated-transaction-acceptance.json", workflow)
        self.assertIn("chr-integrated-transaction-prechange-export.rsc", workflow)
        self.assertNotIn(
            "evidence/routercfg-prechange-system.backup\n            /tmp/chr-download.sha256",
            workflow,
        )


if __name__ == "__main__":
    unittest.main()
