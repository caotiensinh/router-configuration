import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
PROBE = ROOT / "lab" / "chr" / "debug_qos_recovery_paths.py"
HARNESS = ROOT / "lab" / "chr" / "run_qos_recovery_debug_lane.sh"
WORKFLOW = ROOT / ".github" / "workflows" / "chr-qos-recovery-debug.yml"


class CHRQoSRecoveryDebugContractTests(unittest.TestCase):
    def test_three_fallback_formulations_are_independent(self):
        source = PROBE.read_text(encoding="utf-8")
        for lane in (
            "explicit-default-global-hierarchy",
            "interface-prerouting-dscp-hierarchy",
            "global-siblings-no-mark",
        ):
            self.assertIn(lane, source)
        self.assertIn("new-packet-mark={flat._quote(DEFAULT_MARK)}", source)
        self.assertIn("packet-mark=no-mark queue=default-small", source)
        self.assertIn("parent=global packet-mark=no-mark", source)

    def test_explicit_default_fallback_aggregates_two_marked_children(self):
        source = PROBE.read_text(encoding="utf-8")
        self.assertIn("default_classifier_packet_delta", source)
        self.assertIn("default_parent_packet_delta", source)
        self.assertIn("special_parent_packet_delta", source)
        self.assertIn("special_classifier_packet_delta", source)
        self.assertIn('"aggregate_parent_verified": lane != "global-siblings-no-mark"', source)

    def test_debug_only_boundary_is_fail_closed(self):
        source = PROBE.read_text(encoding="utf-8")
        self.assertIn('"production_packet_flow_acceptance": False', source)
        self.assertIn('"production_renderer_modified": False', source)
        self.assertIn('"production_writer_available": False', source)
        self.assertIn('"write_authorized": False', source)
        self.assertIn('"physical_router_targeted": False', source)

    def test_harness_uses_official_disposable_chr_and_settle_windows(self):
        source = HARNESS.read_text(encoding="utf-8")
        self.assertIn("-snapshot", source)
        self.assertIn("127.0.0.1:9897-:80", source)
        self.assertEqual(source.count("for attempt in $(seq 1 20)"), 2)
        self.assertIn("sleep 0.25", source)
        self.assertIn('send_probe 0 "${DEFAULT_PORT}"', source)
        self.assertIn('send_probe 46 "${SPECIAL_PORT}"', source)
        self.assertNotIn("192.168.11.", source)
        self.assertNotIn("ROUTEROS_PASSWORD", source)

    def test_workflow_runs_all_recovery_lanes_without_fail_fast(self):
        source = WORKFLOW.read_text(encoding="utf-8")
        self.assertIn('CHR_VERSION: "7.24.1"', source)
        self.assertIn("fail-fast: false", source)
        for lane in (
            "explicit-default-global-hierarchy",
            "interface-prerouting-dscp-hierarchy",
            "global-siblings-no-mark",
        ):
            self.assertIn(lane, source)
        self.assertIn("run_qos_recovery_debug_lane.sh", source)
        self.assertIn("retention-days: 14", source)
        self.assertNotIn("192.168.11.", source)
        self.assertNotIn("ROUTEROS_PASSWORD", source)


if __name__ == "__main__":
    unittest.main()
