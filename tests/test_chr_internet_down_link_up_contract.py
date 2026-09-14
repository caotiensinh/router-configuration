import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


class ChrInternetDownLinkUpContractTests(unittest.TestCase):
    def test_wrapper_preserves_link_and_removes_only_health_endpoints(self):
        text = (ROOT / "lab/chr/run_packet_flow_link_up_failure.sh").read_text(encoding="utf-8")
        self.assertIn('ip addr del 1.1.1.1/32 dev lo', text)
        self.assertIn('ip addr del 8.8.8.8/32 dev lo', text)
        self.assertIn('ip addr add 1.1.1.1/32 dev lo', text)
        self.assertIn('ip addr add 8.8.8.8/32 dev lo', text)
        self.assertNotIn('new_fail = \'sudo ip link set', text)
        self.assertIn('evaluate_link_up_failure_state.py', text)
        self.assertIn('verify_link_up_recursive_failover.py', text)
        self.assertIn('expected exactly one {label} line', text)
        self.assertIn('expected exactly five packet-flow verifier call sites', text)
        self.assertIn('could not isolate PCC-only diagnostic block', text)

    def test_recursive_verifier_uses_base_renderer_without_pcc(self):
        text = (ROOT / "lab/chr/verify_link_up_recursive_failover.py").read_text(encoding="utf-8")
        self.assertIn('RouterOSSafeSubsetRenderer().render(flow._build_ir())', text)
        self.assertIn('requires exactly 17 base commands', text)
        self.assertNotIn('render_routeros_pcc', text)
        self.assertIn('preferred WAN10', text)
        self.assertIn('flows did not move completely to WAN1', text)
        self.assertIn('production_writer_available', text)
        self.assertIn('write_authorized', text)

    def test_workflow_is_opt_in_by_commit_prefix(self):
        text = (ROOT / ".github/workflows/chr-internet-down-link-up.yml").read_text(encoding="utf-8")
        self.assertIn("ci(chr-linkup):", text)
        self.assertIn("run_packet_flow_link_up_failure.sh", text)
        self.assertIn("chr-internet-down-link-up-${{ github.sha }}", text)
        self.assertIn("production", (ROOT / "lab/chr/evaluate_link_up_failure_state.py").read_text(encoding="utf-8"))


if __name__ == "__main__":
    unittest.main()
