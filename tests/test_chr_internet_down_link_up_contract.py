import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


class ChrInternetDownLinkUpContractTests(unittest.TestCase):
    def test_wrapper_blackholes_upstream_without_lowering_link(self):
        text = (ROOT / "lab/chr/run_packet_flow_link_up_failure.sh").read_text(encoding="utf-8")
        self.assertIn('tc qdisc replace dev "${V_WAN10_NS}" root netem loss 100%', text)
        self.assertIn('tc qdisc del dev "${V_WAN10_NS}" root', text)
        self.assertNotIn('new_fail = \'sudo ip link set', text)
        self.assertNotIn('ip addr del 1.1.1.1/32', text)
        self.assertIn('linkup-namespace-qdisc.txt', text)
        self.assertIn('evaluate_link_up_failure_state.py', text)
        self.assertIn('verify_link_up_recursive_failover.py', text)
        self.assertIn('expected exactly one {label} line', text)
        self.assertIn('expected exactly five packet-flow verifier call sites', text)
        self.assertIn('could not isolate PCC-only diagnostic block', text)

    def test_link_state_evaluator_requires_netem_blackhole_and_link_up(self):
        text = (ROOT / "lab/chr/evaluate_link_up_failure_state.py").read_text(encoding="utf-8")
        self.assertIn('"netem" in text and "loss 100%" in text', text)
        self.assertIn('upstream_packet_blackhole', text)
        self.assertIn('wan10_namespace_egress_netem_loss_100_percent', text)
        self.assertIn('routeros_ether2_running', text)
        self.assertNotIn('health_probe_addresses_removed', text)

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


if __name__ == "__main__":
    unittest.main()
