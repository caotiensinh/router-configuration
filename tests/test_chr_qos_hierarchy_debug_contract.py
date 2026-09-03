import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
PROBE = ROOT / "lab" / "chr" / "debug_qos_hierarchy_paths.py"
HARNESS = ROOT / "lab" / "chr" / "run_qos_hierarchy_debug_lane.sh"
WORKFLOW = ROOT / ".github" / "workflows" / "chr-qos-hierarchy-debug.yml"


class CHRQoSHierarchyDebugContractTests(unittest.TestCase):
    def test_probe_contains_five_independent_attachment_and_hierarchy_lanes(self):
        source = PROBE.read_text(encoding="utf-8")
        for lane in (
            "prod-dscp-global-single",
            "prerouting-port-interface-single",
            "port-global-hierarchy",
            "prod-dscp-global-hierarchy",
            "prerouting-dscp-global-hierarchy",
        ):
            self.assertIn(lane, source)
        self.assertIn('parent="global"', source)
        self.assertIn('parent=WAN', source)
        self.assertIn('parent=global queue=default-small', source)
        self.assertIn('priority=1', source)
        self.assertIn('limit-at=10M', source)

    def test_hierarchy_evaluator_requires_parent_owned_default_and_marked_child(self):
        source = PROBE.read_text(encoding="utf-8")
        self.assertIn("default_parent <= 0", source)
        self.assertIn("default_child != 0 or default_classifier != 0", source)
        self.assertIn("special_classifier <= 0", source)
        self.assertIn("special_child <= 0", source)
        self.assertIn("special_parent <= 0", source)
        self.assertIn('"default_owned_by_parent": True', source)
        self.assertIn('"special_owned_by_child": True', source)

    def test_debug_probe_cannot_claim_production_acceptance_or_writer(self):
        source = PROBE.read_text(encoding="utf-8")
        self.assertIn('"production_packet_flow_acceptance": False', source)
        self.assertIn('"production_renderer_modified": False', source)
        self.assertIn('"production_writer_available": False', source)
        self.assertIn('"write_authorized": False', source)
        self.assertIn('"physical_router_targeted": False', source)

    def test_harness_uses_bounded_settle_windows_and_disposable_loopback_chr(self):
        source = HARNESS.read_text(encoding="utf-8")
        self.assertIn("-snapshot", source)
        self.assertIn("127.0.0.1:9896-:80", source)
        self.assertGreaterEqual(source.count("for attempt in $(seq 1 20)"), 3)
        self.assertIn("sleep 0.25", source)
        self.assertIn("send_probe 0", source)
        self.assertIn('send_probe "${SPECIAL_DSCP}"', source)
        self.assertNotIn("192.168.11.", source)
        self.assertNotIn("ROUTEROS_PASSWORD", source)

    def test_workflow_runs_all_lanes_independently_on_official_chr(self):
        source = WORKFLOW.read_text(encoding="utf-8")
        self.assertIn('CHR_VERSION: "7.24.1"', source)
        self.assertIn("fail-fast: false", source)
        for lane in (
            "prod-dscp-global-single",
            "prerouting-port-interface-single",
            "port-global-hierarchy",
            "prod-dscp-global-hierarchy",
            "prerouting-dscp-global-hierarchy",
        ):
            self.assertIn(lane, source)
        self.assertIn("run_qos_hierarchy_debug_lane.sh", source)
        self.assertIn("retention-days: 14", source)
        self.assertNotIn("192.168.11.", source)
        self.assertNotIn("ROUTEROS_PASSWORD", source)


if __name__ == "__main__":
    unittest.main()
