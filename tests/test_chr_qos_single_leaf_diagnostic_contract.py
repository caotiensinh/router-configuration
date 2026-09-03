import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
PROBE = ROOT / "lab" / "chr" / "diagnose_qos_single_leaf.py"
HARNESS = ROOT / "lab" / "chr" / "run_qos_single_leaf_diagnostic.sh"
WORKFLOW = ROOT / ".github" / "workflows" / "chr-qos-single-leaf-diagnostic.yml"


class CHRQoSSingleLeafDiagnosticContractTests(unittest.TestCase):
    def test_probe_installs_exactly_one_selected_leaf_per_mode(self):
        source = PROBE.read_text(encoding="utf-8")
        self.assertIn('SINGLE_DEFAULT_LEAF = "routercfg-qos-single-default"', source)
        self.assertIn('SINGLE_EF_LEAF = "routercfg-qos-single-ef"', source)
        self.assertIn('parent=global', source)
        self.assertIn('"sibling_leaf_present": False', source)
        self.assertIn('"priority_configured": False', source)
        self.assertIn('"limit_at_configured": False', source)
        self.assertNotIn("priority=1", source)
        self.assertNotIn("limit-at=10M", source)

    def test_default_mode_adds_only_bounded_default_mark(self):
        source = PROBE.read_text(encoding="utf-8")
        self.assertIn("packet-mark=no-mark action=mark-packet", source)
        self.assertIn("new-packet-mark={flat._quote(mark)}", source)
        self.assertIn("flat.DEFAULT_COMMENT", source)
        self.assertNotIn("routercfg:lab:qos-flat:ef", source)

    def test_ef_mode_reuses_production_mark_without_lab_ef_mangle(self):
        source = PROBE.read_text(encoding="utf-8")
        self.assertIn('mark = ef_mark', source)
        self.assertIn('comment = ef_comment', source)
        self.assertIn('"production_mark_source_retained": mode == "ef"', source)
        self.assertIn('str(selected_rule.get("dscp") or "") != "46"', source)

    def test_probe_uses_print_stats_and_never_claims_production_acceptance(self):
        source = PROBE.read_text(encoding="utf-8")
        self.assertIn("flat._stats_rows(admin)", source)
        self.assertIn('"counter_source": "queue_tree_print_stats"', source)
        self.assertIn('"diagnostic_packet_flow_acceptance": True', source)
        self.assertIn('"production_packet_flow_acceptance": False', source)
        self.assertIn('"production_renderer_modified": False', source)
        self.assertIn('"production_writer_available": False', source)
        self.assertIn('"transport_exposed_to_product": False', source)
        self.assertIn('"write_authorized": False', source)
        self.assertIn('"physical_router_targeted": False', source)

    def test_harness_runs_default_then_ef_for_builtin_and_fq_codel(self):
        source = HARNESS.read_text(encoding="utf-8")
        self.assertIn("run_phase default default-small default-default-small 0 42000", source)
        self.assertIn("run_phase ef default-small ef-default-small 46 44000", source)
        self.assertIn("run_phase default routercfg-qos-fq default-fq-codel 0 46000", source)
        self.assertIn("run_phase ef routercfg-qos-fq ef-fq-codel 46 48000", source)
        self.assertIn("verify_qos_packet_flow_v2.py", source)
        self.assertIn("diagnose_qos_single_leaf.py", source)
        self.assertIn("-snapshot", source)
        self.assertIn("hostfwd=tcp:127.0.0.1:9892-:80", source)
        self.assertNotIn("192.168.11.", source)
        self.assertNotIn("ROUTEROS_PASSWORD", source)

    def test_linux_dataplane_interface_names_stay_within_kernel_limit(self):
        source = HARNESS.read_text(encoding="utf-8")
        for name in ("brqswan", "brqscore", "tapqswan", "tapqscore", "vqs-wan-br", "vqs-wan-ns", "vqs-core-br", "vqs-core-ns"):
            self.assertLessEqual(len(name), 15)
            self.assertIn(name, source)

    def test_workflow_is_official_disposable_chr_and_sanitized(self):
        if not WORKFLOW.exists():
            self.skipTest("single-leaf workflow wiring commit not present yet")
        source = WORKFLOW.read_text(encoding="utf-8")
        self.assertIn('CHR_VERSION: "7.24.1"', source)
        self.assertIn("run_qos_single_leaf_diagnostic.sh", source)
        self.assertIn("https://download.mikrotik.com/routeros/${CHR_VERSION}/chr-${CHR_VERSION}.img.zip", HARNESS.read_text(encoding="utf-8"))
        self.assertIn("chr-qos-single-leaf-${{ github.sha }}", source)
        self.assertNotIn("192.168.11.", source)
        self.assertNotIn("ROUTEROS_PASSWORD", source)
        artifact_section = source.split("name: Preserve sanitized single-leaf diagnostic evidence", 1)[1]
        self.assertNotIn(".img", artifact_section)
        self.assertNotIn("serial.log", artifact_section)


if __name__ == "__main__":
    unittest.main()
