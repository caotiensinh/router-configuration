import importlib.util
import json
import sys
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
CHR_DIR = ROOT / "lab" / "chr"
VERIFY = CHR_DIR / "verify_packet_flow_behavior.py"
HARNESS = CHR_DIR / "run_packet_flow_acceptance.sh"
WORKFLOW = ROOT / ".github" / "workflows" / "chr-packet-flow.yml"
DIAGNOSTIC = CHR_DIR / "diagnose_pcc_runtime.py"


def load(path: Path, name: str):
    sys.path.insert(0, str(CHR_DIR))
    try:
        spec = importlib.util.spec_from_file_location(name, path)
        module = importlib.util.module_from_spec(spec)
        assert spec and spec.loader
        spec.loader.exec_module(module)
        return module
    finally:
        sys.path.pop(0)


class CHRPacketFlowContractTests(unittest.TestCase):
    def test_combined_fixture_is_exact_recursive_plus_pcc_plan(self):
        module = load(VERIFY, "verify_packet_flow_fixture")
        commands = module._combined_commands()
        self.assertEqual(len(commands), 38)
        sections = [str(item.get("section") or "") for item in commands]
        self.assertEqual(sections.count("firewall_mangle"), 13)
        self.assertEqual(sections.count("pcc_policy_route"), 8)

    def test_harness_uses_four_nics_and_isolated_network_namespaces(self):
        source = HARNESS.read_text(encoding="utf-8")
        for required in (
            'NS_WAN10="rc-wan10"',
            'NS_WAN1="rc-wan1"',
            'NS_CORE="rc-core"',
            'TAP_WAN10="tap-rc-w10"',
            'TAP_WAN1="tap-rc-w1"',
            'TAP_CORE="tap-rc-core"',
            "-netdev user,id=mgmt",
            "-netdev tap,id=wan10",
            "-netdev tap,id=wan1",
            "-netdev tap,id=core",
            "required = {'ether1', 'ether2', 'ether3', 'ether4'}",
        ):
            self.assertIn(required, source)
        self.assertIn('ip addr add "${SERVICE_IP}/32" dev lo', source)
        self.assertIn("--tag WAN10", source)
        self.assertIn("--tag WAN1", source)

    def test_harness_is_fail_closed_and_runs_runtime_invalid_rule_diagnostic(self):
        source = HARNESS.read_text(encoding="utf-8")
        self.assertIn("set -Eeuo pipefail", source)
        self.assertNotIn("set +e", source)
        self.assertIn("diagnose_pcc_runtime.py", source)
        self.assertIn("pcc-runtime-diagnostic.json", source)
        self.assertIn("managed_invalid_count", source)
        self.assertIn("raise SystemExit(19)", source)

    def test_harness_measures_normal_failure_and_recovery_without_live_credentials(self):
        source = HARNESS.read_text(encoding="utf-8")
        self.assertIn("flows-normal.json", source)
        self.assertIn("routes-wan10-failed.json", source)
        self.assertIn("flows-failover.json", source)
        self.assertIn("routes-recovered.json", source)
        self.assertIn("flows-recovery.json", source)
        self.assertIn('sudo ip link set "${V_WAN10_BR}" down', source)
        self.assertIn('sudo ip link set "${V_WAN10_BR}" up', source)
        self.assertIn("packet-flow-acceptance.json", source)
        for forbidden in (
            "ROUTEROS_PASSWORD",
            "ROUTEROS_USERNAME",
            "vault://",
            "192.168.11.",
            "production-router",
        ):
            self.assertNotIn(forbidden, source)

    def test_runtime_diagnostic_is_disposable_chr_only_and_cleans_itself(self):
        source = DIAGNOSTIC.read_text(encoding="utf-8")
        self.assertIn("LoopbackCHRAdmin", source)
        self.assertIn("assert_disposable_chr", source)
        self.assertIn("_delete_diagnostics(admin)", source)
        self.assertIn("routeros_cli_import_existing_mark_and_modulus_matrix", source)
        self.assertIn("mc_existing_plain", source)
        self.assertIn("mc_existing_pcc_2_1", source)
        self.assertIn("mc_existing_pcc_11_1", source)
        self.assertIn("mc_existing_pcc_11_10", source)
        self.assertIn("mc_11_1_state_nomark_dst", source)
        self.assertIn("mc_11_1_full", source)
        self.assertIn("routing_mark_table_only", source)
        self.assertIn("routing_mark_existing_connection", source)
        self.assertIn("_execute_import", source)
        self.assertIn('"production_writer_available": False', source)
        self.assertIn('"write_authorized": False', source)
        for forbidden in (
            "ROUTEROS_PASSWORD",
            "ROUTEROS_USERNAME",
            "192.168.11.",
            "paramiko",
            "requests.",
        ):
            self.assertNotIn(forbidden, source)

    def test_acceptance_evaluator_requires_10_to_1_and_full_failover(self):
        module = load(VERIFY, "verify_packet_flow_evaluate")
        with tempfile.TemporaryDirectory() as temp_dir:
            temp = Path(temp_dir)

            def write(name, payload):
                path = temp / name
                path.write_text(json.dumps(payload), encoding="utf-8")
                return path

            normal = write(
                "normal.json",
                {"requested_flows": 220, "successful_flows": 220, "tags": {"WAN10": 200, "WAN1": 20}},
            )
            failover = write(
                "failover.json",
                {"requested_flows": 220, "successful_flows": 220, "tags": {"WAN1": 220}},
            )
            recovery = write(
                "recovery.json",
                {"requested_flows": 220, "successful_flows": 220, "tags": {"WAN10": 198, "WAN1": 22}},
            )
            failed_routes = write("failed-routes.json", {"ok": True, "expected": "wan10_failed"})
            recovered_routes = write("recovered-routes.json", {"ok": True, "expected": "recovered"})
            output = temp / "result.json"
            result = module.evaluate(
                normal_path=normal,
                failover_path=failover,
                recovery_path=recovery,
                failed_route_path=failed_routes,
                recovered_route_path=recovered_routes,
                output=output,
            )
            self.assertTrue(result["ok"])
            self.assertEqual(result["acceptance"], "PASS")
            self.assertGreaterEqual(result["wan10_failure"]["wan1_share"], 0.98)

    def test_workflow_is_explicitly_scoped_to_chr_flow_trigger_and_evidence(self):
        source = WORKFLOW.read_text(encoding="utf-8")
        self.assertIn("ci(chr-flow):", source)
        self.assertIn("run_packet_flow_acceptance.sh", source)
        self.assertIn("qemu-system-x86", source)
        self.assertIn("iproute2", source)
        self.assertIn("actions/cache/restore@v4", source)
        self.assertIn("actions/upload-artifact@v4", source)
        self.assertIn("chr-packet-flow-${{ github.sha }}", source)
        self.assertNotIn("ROUTEROS_PASSWORD", source)


if __name__ == "__main__":
    unittest.main()
