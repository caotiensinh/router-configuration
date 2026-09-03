import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
PROBE = ROOT / "lab" / "chr" / "debug_qos_multi_path.py"
HARNESS = ROOT / "lab" / "chr" / "run_qos_multi_path_lane.sh"
WIRE = ROOT / "lab" / "chr" / "run_qos_wire_dscp_observation.sh"
WORKFLOW = ROOT / ".github" / "workflows" / "chr-qos-multi-path-debug.yml"


class CHRQoSMultiPathDebugContractTests(unittest.TestCase):
    def test_probe_contains_four_independent_hypotheses(self):
        source = PROBE.read_text(encoding="utf-8")
        for lane in (
            "dscp-observe",
            "interface-parent-forward",
            "port-classifier-global",
            "connection-mark-global",
        ):
            self.assertIn(lane, source)
        self.assertIn("parent={flat._quote(WAN)}", source)
        self.assertIn("src-port=46000-46079", source)
        self.assertIn("action=mark-connection", source)
        self.assertIn("dscp=46 action=passthrough", source)

    def test_debug_probe_cannot_claim_production_acceptance(self):
        source = PROBE.read_text(encoding="utf-8")
        self.assertIn('"production_packet_flow_acceptance": False', source)
        self.assertIn('"production_renderer_modified": False', source)
        self.assertIn('"production_writer_available": False', source)
        self.assertIn('"write_authorized": False', source)
        self.assertIn('"physical_router_targeted": False', source)

    def test_wire_observer_proves_generator_without_routeros_claim(self):
        source = WIRE.read_text(encoding="utf-8")
        self.assertIn("tcpdump", source)
        self.assertIn("tos 0xb8", source)
        self.assertIn("--dscp 46", source)
        self.assertIn("'routeros_behavior_claimed': False", source)
        self.assertIn("'production_packet_flow_acceptance': False", source)

    def test_workflow_runs_matrix_fail_fast_false_on_official_chr(self):
        source = WORKFLOW.read_text(encoding="utf-8")
        self.assertIn('CHR_VERSION: "7.24.1"', source)
        self.assertIn("fail-fast: false", source)
        self.assertIn("dscp-observe", source)
        self.assertIn("interface-parent-forward", source)
        self.assertIn("port-classifier-global", source)
        self.assertIn("connection-mark-global", source)
        self.assertIn("run_qos_wire_dscp_observation.sh", source)
        self.assertIn("run_qos_multi_path_lane.sh", source)
        self.assertNotIn("192.168.11.", source)
        self.assertNotIn("ROUTEROS_PASSWORD", source)

    def test_harness_remains_disposable_and_bounded(self):
        source = HARNESS.read_text(encoding="utf-8")
        self.assertIn("-snapshot", source)
        self.assertIn("127.0.0.1:9895-:80", source)
        self.assertIn("for attempt in $(seq 1 20)", source)
        self.assertIn("production QoS facts", source)
        self.assertNotIn("192.168.11.", source)


if __name__ == "__main__":
    unittest.main()
