import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
WORKFLOW = ROOT / ".github" / "workflows" / "chr-secure-reader-https.yml"
BOOTSTRAP = ROOT / "lab" / "chr" / "bootstrap_secure_acceptance.py"
BOUNDARY = ROOT / "lab" / "chr" / "verify_reader_write_denied.py"


class CHRSecureReaderHTTPSContractTests(unittest.TestCase):
    def test_workflow_uses_official_disposable_chr_snapshot(self):
        text = WORKFLOW.read_text(encoding="utf-8")
        self.assertIn('CHR_VERSION: "7.24.1"', text)
        self.assertIn("download.mikrotik.com/routeros", text)
        self.assertIn("-snapshot", text)
        self.assertIn("127.0.0.1:9180-:80", text)
        self.assertIn("127.0.0.1:9443-:443", text)

    def test_workflow_reuses_dedicated_reader_and_verified_https_boundaries(self):
        text = WORKFLOW.read_text(encoding="utf-8")
        self.assertIn("bootstrap_secure_acceptance.py", text)
        self.assertIn("verify_reader_write_denied.py", text)
        self.assertIn("SSL_CERT_FILE", text)
        self.assertIn("tls-negative.json", text)
        self.assertIn("UNTRUSTED_CA_REJECTED", text)
        self.assertNotIn("--no-verify-tls", text)
        self.assertNotIn("ROUTEROS_LAB_INSECURE_TLS", text)

    def test_acceptance_requires_all_production_read_surfaces(self):
        text = WORKFLOW.read_text(encoding="utf-8")
        self.assertIn("from router_configuration.routeros_discovery import READ_SURFACES", text)
        self.assertIn('assert failed == []', text)
        self.assertIn('assert sorted(successful) == expected', text)
        self.assertIn('"surface_count": len(expected)', text)

    def test_acceptance_is_fail_closed_for_write_and_tls(self):
        text = WORKFLOW.read_text(encoding="utf-8")
        self.assertIn('assert boundary["write_authorized"] is False', text)
        self.assertIn('assert boundary["write_denial_verified_by_readback"] is True', text)
        self.assertIn('assert negative["tls_verification_bypass_used"] is False', text)
        self.assertIn('"production_writer_available": False', text)
        self.assertIn('"physical_router_targeted": False', text)
        self.assertIn('"operator_attested": False', text)

    def test_reader_policy_source_remains_minimal(self):
        text = BOOTSTRAP.read_text(encoding="utf-8")
        self.assertIn('READER_POLICY = "read,api,rest-api"', text)
        self.assertIn('"write"', text)
        boundary = BOUNDARY.read_text(encoding="utf-8")
        self.assertIn("dedicated reader unexpectedly performed a write operation", boundary)
        self.assertIn("probe_marker_absent_after_denial", boundary)

    def test_ephemeral_reader_credentials_are_not_artifacted(self):
        text = WORKFLOW.read_text(encoding="utf-8")
        self.assertIn("rm -f /tmp/routercfg-reader.json", text)
        artifact_section = text.split("Preserve sanitized acceptance evidence", 1)[1]
        self.assertNotIn("/tmp/routercfg-reader.json\n", artifact_section)


if __name__ == "__main__":
    unittest.main()
