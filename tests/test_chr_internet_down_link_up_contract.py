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
        self.assertIn('expected exactly one failure injection line', text)
        self.assertIn('expected exactly one recovery injection line', text)

    def test_workflow_is_opt_in_by_commit_prefix(self):
        text = (ROOT / ".github/workflows/chr-internet-down-link-up.yml").read_text(encoding="utf-8")
        self.assertIn("ci(chr-linkup):", text)
        self.assertIn("run_packet_flow_link_up_failure.sh", text)
        self.assertIn("chr-internet-down-link-up-${{ github.sha }}", text)
        self.assertIn("production", (ROOT / "lab/chr/evaluate_link_up_failure_state.py").read_text(encoding="utf-8"))


if __name__ == "__main__":
    unittest.main()
