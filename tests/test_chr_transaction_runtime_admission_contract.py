import importlib.util
import sys
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "lab" / "chr" / "verify_transaction_runtime_admission.py"
WORKFLOW = ROOT / ".github" / "workflows" / "chr-transaction-runtime-admission.yml"


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


class CHRTransactionRuntimeAdmissionContractTests(unittest.TestCase):
    def test_render_plan_is_deterministic_generation_only_and_exact_fixture(self):
        module = load(SCRIPT, "verify_transaction_runtime_admission_contract")
        fixture = module.fixture_builder.build_syntax_fixture()
        first = module._render_plan(fixture)
        second = module._render_plan(fixture)
        self.assertEqual(first, second)
        self.assertEqual(len(first["commands"]), 38)
        self.assertEqual(len(first["render_sha256"]), 64)
        self.assertEqual(first["blocked_operations"], [])
        self.assertFalse(first["transport_present"])
        self.assertFalse(first["apply_available"])
        self.assertFalse(first["write_authorized"])

    def test_source_admits_before_first_mutation_capable_runtime_call(self):
        source = SCRIPT.read_text(encoding="utf-8")
        admission = source.index("admit_disposable_chr_candidate(")
        runtime = source.index("runtime_rollback.verify_mutation_rollback(")
        self.assertLess(admission, runtime)
        self.assertIn("validate_transaction_backup_evidence(", source)
        self.assertIn('"target_kind": "disposable_chr"', source)
        self.assertIn('"snapshot_mode": True', source)
        self.assertIn('"physical_router_targeted": False', source)
        self.assertIn('"production": False', source)
        self.assertIn('"recovery_verification_claimed": False', source)
        self.assertIn('"operator_attestation_claimed": False', source)
        self.assertIn('"production_writer_available": False', source)
        self.assertIn('"transport_exposed_to_product": False', source)
        self.assertIn('"write_authorized": False', source)

    def test_source_does_not_embed_runtime_credentials_or_generic_writer(self):
        source = SCRIPT.read_text(encoding="utf-8")
        for forbidden in (
            "ROUTEROS_PASSWORD",
            "private_key",
            "requests.",
            "socket.",
            "subprocess",
            "paramiko",
        ):
            self.assertNotIn(forbidden, source)

    def test_workflow_is_official_disposable_chr_snapshot_only(self):
        workflow = WORKFLOW.read_text(encoding="utf-8")
        self.assertIn("CHR_VERSION: \"7.24.1\"", workflow)
        self.assertIn("download.mikrotik.com/routeros/${CHR_VERSION}", workflow)
        self.assertIn("-snapshot", workflow)
        self.assertIn("127.0.0.1:9380", workflow)
        self.assertIn("verify_transaction_runtime_admission.py", workflow)
        self.assertIn('--workflow-sha "$GITHUB_SHA"', workflow)
        self.assertIn("admission_completed_before_runtime_call", workflow)
        self.assertIn("recovery_verification_claimed", workflow)
        self.assertIn("operator_attestation_claimed", workflow)
        self.assertIn("binary_payload_present", workflow)
        self.assertNotIn(".backup\n", workflow)
        self.assertNotIn("ROUTEROS_PASSWORD", workflow)


if __name__ == "__main__":
    unittest.main()
