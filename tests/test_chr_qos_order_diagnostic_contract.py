import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
DIAGNOSTIC = ROOT / "lab" / "chr" / "diagnose_qos_creation_order.py"
WORKFLOW = ROOT / ".github" / "workflows" / "chr-qos-order-diagnostic.yml"


class CHRQoSCreationOrderDiagnosticContractTests(unittest.TestCase):
    def test_diagnostic_is_order_focused_and_sanitized(self):
        source = DIAGNOSTIC.read_text(encoding="utf-8")
        for required in (
            'MODES = {"batch-mangle", "interleaved", "leaves-first"}',
            '"queue/type"',
            '"queue/tree"',
            '"ip/firewall/mangle"',
            '"voice_mangle"',
            '"default_mangle"',
            '"voice_leaf"',
            '"default_leaf"',
            '"throughput_acceptance": False',
            '"latency_acceptance": False',
            '"secrets_present": False',
            '"physical_router_targeted": False',
            '"production_writer_available": False',
            '"write_authorized": False',
        ):
            self.assertIn(required, source)
        for forbidden in (
            "ROUTEROS_PASSWORD",
            "ROUTEROS_USERNAME",
            "192.168.11.",
            "secrets.",
        ):
            self.assertNotIn(forbidden, source)

    def test_workflow_uses_one_fresh_snapshot_per_creation_order_mode(self):
        source = WORKFLOW.read_text(encoding="utf-8")
        for required in (
            "diag(chr-qos-order):",
            'CHR_VERSION: "7.24.1"',
            "mode: [batch-mangle, interleaved, leaves-first]",
            "-snapshot",
            "hostfwd=tcp:127.0.0.1:9790-:80",
            "diagnose_qos_creation_order.py",
            'qos-order-${{ matrix.mode }}.json',
            'chr-qos-order-${{ matrix.mode }}-${{ github.sha }}',
            "physical_router_targeted",
            "production_writer_available",
            "write_authorized",
        ):
            self.assertIn(required, source)
        for forbidden in (
            "ROUTEROS_PASSWORD",
            "ROUTEROS_USERNAME",
            "secrets.",
            "192.168.11.",
        ):
            self.assertNotIn(forbidden, source)


if __name__ == "__main__":
    unittest.main()
