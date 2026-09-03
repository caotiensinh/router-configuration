import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
PROBE = ROOT / "lab" / "chr" / "verify_qos_parent_default_runtime.py"
WORKFLOW = ROOT / ".github" / "workflows" / "chr-qos-parent-default-runtime.yml"


class CHRQoSParentDefaultRuntimeContractTests(unittest.TestCase):
    def test_probe_uses_production_renderer_instead_of_parallel_apply_logic(self):
        source = PROBE.read_text(encoding="utf-8")
        self.assertIn("from router_configuration.routeros_qos_renderer import render_routeros_qos", source)
        self.assertIn("plan = render_routeros_qos(ir=_runtime_ir()).as_dict()", source)
        self.assertIn("_script_from_plan(plan)", source)
        self.assertNotIn("def _apply_script(", source)
        self.assertNotIn("/queue/tree/add", source)
        self.assertNotIn("/ip/firewall/mangle/add", source)

    def test_probe_requires_runtime_validity_and_exact_owned_rollback(self):
        source = PROBE.read_text(encoding="utf-8")
        self.assertIn("invalid_managed_objects", source)
        self.assertIn("disabled_managed_objects", source)
        self.assertIn("default_mangle_count", source)
        self.assertIn("rollback_sha != baseline_sha", source)
        self.assertIn('f\'/queue/tree/remove [find where name="{child}"]\'', source)
        self.assertIn('f\'/queue/tree/remove [find where name="{parent}"]\'', source)
        self.assertIn('f\'/ip/firewall/mangle/remove [find where comment="{comment}"]\'', source)
        self.assertIn('f\'/queue/type/remove [find where name="{qtype}"]\'', source)

    def test_runtime_gate_does_not_overclaim_packet_flow_or_production_write(self):
        source = PROBE.read_text(encoding="utf-8")
        self.assertIn('"packet_flow_acceptance": False', source)
        self.assertIn('"latency_performance_claimed": False', source)
        self.assertIn('"production_writer_available": False', source)
        self.assertIn('"transport_exposed_to_product": False', source)
        self.assertIn('"write_authorized": False', source)
        self.assertIn('"physical_router_targeted": False', source)

    def test_workflow_is_official_disposable_chr_snapshot_only(self):
        source = WORKFLOW.read_text(encoding="utf-8")
        self.assertIn('CHR_VERSION: "7.24.1"', source)
        self.assertIn("https://download.mikrotik.com/routeros/${CHR_VERSION}/chr-${CHR_VERSION}.img.zip", source)
        self.assertIn("-snapshot", source)
        self.assertIn("hostfwd=tcp:127.0.0.1:9781-:80", source)
        self.assertIn("verify_qos_parent_default_runtime.py", source)
        self.assertIn("chr-qos-parent-default-runtime-${{ github.sha }}", source)
        self.assertNotIn("192.168.11.", source)
        self.assertNotIn("ROUTEROS_PASSWORD", source)
        self.assertNotIn("private-key", source.lower())

    def test_workflow_artifact_excludes_image_and_serial_runtime_files(self):
        source = WORKFLOW.read_text(encoding="utf-8")
        artifact_section = source.split("name: Preserve sanitized QoS runtime evidence", 1)[1]
        artifact_section = artifact_section.split("name: Stop disposable CHR", 1)[0]
        self.assertIn("result.json", artifact_section)
        self.assertIn("chr-resource.json", artifact_section)
        self.assertIn("chr-interfaces.json", artifact_section)
        self.assertIn("chr-qos-parent-default-download.sha256", artifact_section)
        self.assertNotIn(".img", artifact_section)
        self.assertNotIn("serial.log", artifact_section)


if __name__ == "__main__":
    unittest.main()
