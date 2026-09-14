import importlib.util
import sys
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
CHR_DIR = ROOT / "lab" / "chr"
VERIFY = CHR_DIR / "verify_transaction_backup_acceptance.py"
WORKFLOW = ROOT / ".github" / "workflows" / "chr-transaction-backup-acceptance.yml"


def load(path: Path, name: str):
    sys.path.insert(0, str(CHR_DIR))
    try:
        spec = importlib.util.spec_from_file_location(name, path)
        module = importlib.util.module_from_spec(spec)
        assert spec and spec.loader
        spec.loader.exec_module(module)
        return module
    finally:
        sys.path.pop(0)


class CHRTransactionBackupAcceptanceContractTests(unittest.TestCase):
    def test_helper_is_disposable_chr_only_and_captures_two_real_backup_forms(self):
        source = VERIFY.read_text(encoding="utf-8")
        self.assertIn("LoopbackCHRAdmin", source)
        self.assertIn("assert_disposable_chr", source)
        self.assertIn('"POST",\n            "export"', source)
        self.assertIn('"system/backup/save"', source)
        self.assertIn('"aes-sha256"', source)
        self.assertIn('"sshpass"', source)
        self.assertIn('"-e"', source)
        self.assertIn("protected_binary_sha256_from_downloaded_bytes", source)
        self.assertIn("build_transaction_backup_set", source)
        self.assertIn("_delete_user(admin, FETCH_USER)", source)
        self.assertIn("_assert_user_absent(admin, FETCH_USER)", source)
        self.assertIn("_assert_files_absent", source)
        self.assertIn('"production_writer_available": False', source)
        self.assertIn('"write_authorized": False', source)

    def test_sanitized_export_rejects_nonredacted_secret_material(self):
        module = load(VERIFY, "verify_transaction_backup_acceptance_contract")
        module._assert_sanitized_export("/ip address\nadd address=192.0.2.1/24\n")
        with self.assertRaises(module.CHRTransactionBackupAcceptanceError):
            module._assert_sanitized_export('/user add name=x password="cleartext"\n')
        with self.assertRaises(module.CHRTransactionBackupAcceptanceError):
            module._assert_sanitized_export('/interface wireguard add private-key="abc"\n')

    def test_workflow_never_uploads_binary_backup_and_forwards_only_lab_ports(self):
        source = WORKFLOW.read_text(encoding="utf-8")
        self.assertIn("hostfwd=tcp:127.0.0.1:9780-:80", source)
        self.assertIn("hostfwd=tcp:127.0.0.1:9822-:22", source)
        self.assertIn("sshpass", source)
        self.assertIn("verify_transaction_backup_acceptance.py", source)
        self.assertIn("chr-transaction-prechange-export.rsc", source)
        self.assertIn("chr-transaction-real-backup.json", source)
        self.assertIn("production_backup_requirements_satisfied", source)
        self.assertIn("protected_binary_sha256_from_downloaded_bytes", source)
        self.assertNotIn("evidence/routercfg-prechange-system.backup\n", source.split("path: |", 1)[1])
        self.assertIn("rm -f evidence/routercfg-prechange-system.backup", source)


if __name__ == "__main__":
    unittest.main()
