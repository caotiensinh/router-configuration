import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
DIAGNOSTIC = ROOT / "lab" / "chr" / "diagnose_qos_runtime.py"
WORKFLOW = ROOT / ".github" / "workflows" / "chr-qos-diagnostic.yml"


class CHRQoSDiagnosticContractTests(unittest.TestCase):
    def test_diagnostic_is_sanitized_and_scoped_to_owned_qos_objects(self):
        source = DIAGNOSTIC.read_text(encoding="utf-8")
        for required in (
            '"ip/firewall/mangle"',
            '"queue/tree"',
            '"queue/type"',
            '"invalid"',
            '"managed_mangle"',
            '"managed_queue_tree"',
            '"managed_queue_type"',
            '"secrets_present": False',
            '"physical_router_targeted": False',
            '"production_writer_available": False',
            '"write_authorized": False',
        ):
            self.assertIn(required, source)
        for forbidden in (
            '"password"',
            '"private-key"',
            '"preshared-key"',
            "ROUTEROS_PASSWORD",
            "ROUTEROS_USERNAME",
            "192.168.11.",
        ):
            self.assertNotIn(forbidden, source)

    def test_workflow_uses_official_disposable_chr_and_only_sanitized_artifacts(self):
        source = WORKFLOW.read_text(encoding="utf-8")
        for required in (
            "diag(chr-qos):",
            'CHR_VERSION: "7.24.1"',
            "https://download.mikrotik.com/routeros/${CHR_VERSION}/chr-${CHR_VERSION}.img.zip",
            "-snapshot",
            "hostfwd=tcp:127.0.0.1:9780-:80",
            "diagnose_qos_runtime.py",
            "qos-diagnostic.json",
            "chr-qos-diagnostic-${{ github.sha }}",
            "diagnostic did not capture an invalid managed mangle row",
        ):
            self.assertIn(required, source)
        artifact_section = source[
            source.index("- name: Preserve sanitized diagnostic evidence"):
            source.index("- name: Require diagnostic to reproduce current failure")
        ]
        self.assertNotIn("serial.log", artifact_section)
        self.assertNotIn(".rsc", artifact_section)
        for forbidden in (
            "ROUTEROS_PASSWORD",
            "ROUTEROS_USERNAME",
            "secrets.",
            "192.168.11.",
        ):
            self.assertNotIn(forbidden, source)


if __name__ == "__main__":
    unittest.main()
