import importlib.util
import sys
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
CHR_DIR = ROOT / "lab" / "chr"
VALIDATOR = CHR_DIR / "verify_firewall_baseline.py"
WORKFLOW = ROOT / ".github" / "workflows" / "chr-firewall-baseline.yml"


def load_validator():
    sys.path.insert(0, str(CHR_DIR))
    try:
        spec = importlib.util.spec_from_file_location("verify_firewall_baseline_contract", VALIDATOR)
        module = importlib.util.module_from_spec(spec)
        assert spec and spec.loader
        spec.loader.exec_module(module)
        return module
    finally:
        sys.path.pop(0)


class CHRFirewallBaselineContractTests(unittest.TestCase):
    def test_fixture_is_exact_topology_plus_enterprise_firewall_plan(self):
        module = load_validator()
        fixture = module._render_fixture("10.0.2.0/24")
        self.assertEqual(fixture["base_command_count"], 4)
        self.assertEqual(fixture["firewall_command_count"], 23)
        self.assertEqual(fixture["command_count"], 27)
        self.assertFalse(fixture["production_writer_available"])
        self.assertFalse(fixture["write_authorized"])

        plan = fixture["firewall_plan"]
        self.assertEqual(plan["management_sources"], ["10.0.2.0/24"])
        self.assertEqual(plan["required_wan_services"][0]["source_cidrs"], ["198.51.100.10/32"])
        command_ids = [item["command_id"] for item in fixture["commands"]]
        anti_spoof = command_ids.index("firewall.30.rule.030-management-antispoof")
        icmp = command_ids.index("firewall.30.rule.040-icmp")
        self.assertLess(anti_spoof, icmp)

        source = "\n".join(str(item["command"]) for item in fixture["commands"])
        self.assertIn('list="routercfg-CORE" interface="ether1"', source)
        self.assertIn('list="routercfg-WAN" interface="ether2"', source)
        self.assertIn('src-address-list="routercfg-MGMT-SOURCES"', source)

    def test_management_network_is_derived_from_live_ether1_state(self):
        module = load_validator()

        class FakeAdmin:
            def request(self, method, path):
                self_method = method
                self_path = path
                assert self_method == "GET"
                assert self_path == "ip/address"
                return 200, [
                    {"interface": "ether2", "address": "192.0.2.2/24"},
                    {"interface": "ether1", "address": "10.0.2.15/24", "dynamic": "true"},
                    {"interface": "ether1", "address": "203.0.113.9/32"},
                ]

        observed_address, observed_network = module._observed_management_network(FakeAdmin())
        self.assertEqual(observed_address, "10.0.2.15/24")
        self.assertEqual(observed_network, "10.0.2.0/24")

    def test_validator_dry_runs_before_apply_and_requires_exact_rollback_digest(self):
        source = VALIDATOR.read_text(encoding="utf-8")
        for required in (
            "LoopbackCHRAdmin",
            "assert_disposable_chr",
            "_observed_management_network",
            "_execute_import_dry_run",
            "mutation._execute_import",
            "dry_run_digest != baseline_digest",
            "mutated_digest == baseline_digest",
            "rollback_digest != baseline_digest",
            "management_path_alive",
            "managed_filter_invalid_count",
            "managed_filter_disabled_count",
            "input_jump_first",
            "management_accept_core_only",
            "wan_input_default_deny",
            "management_source_antispoof_before_icmp",
        ):
            self.assertIn(required, source)
        self.assertIn('"invented": False', source)
        self.assertIn('"physical_router_targeted": False', source)
        for forbidden in (
            "ROUTEROS_PASSWORD",
            "ROUTEROS_USERNAME",
            "192.168.11.",
            "paramiko",
            "requests.",
            "set +e",
        ):
            self.assertNotIn(forbidden, source)

    def test_rollback_removes_only_routercfg_owned_firewall_surfaces(self):
        module = load_validator()
        rollback = module._rollback_script()
        for required in (
            'comment="routercfg:managed:fw:input-jump"',
            'comment="routercfg:managed:fw-stage-guard"',
            'chain="routercfg-input"',
            'chain="routercfg-icmp"',
            'comment~"^routercfg:managed:fw:addr:"',
            'comment~"^routercfg:managed:wan:"',
            'comment="routercfg:managed:core-uplink"',
            'name="routercfg-WAN"',
            'name="routercfg-CORE"',
        ):
            self.assertIn(required, rollback)
        self.assertNotIn("/ip/firewall/filter/remove [find]\n", rollback)
        self.assertNotIn("/ip/firewall/address-list/remove [find]\n", rollback)

    def test_workflow_is_official_disposable_chr_and_always_preserves_evidence(self):
        source = WORKFLOW.read_text(encoding="utf-8")
        for required in (
            "ci(chr-firewall):",
            'CHR_VERSION: "7.24.1"',
            "https://download.mikrotik.com/routeros/${CHR_VERSION}/chr-${CHR_VERSION}.img.zip",
            "-snapshot",
            "hostfwd=tcp:127.0.0.1:9480-:80",
            "verify_firewall_baseline.py",
            "firewall-baseline.json",
            "actions/upload-artifact@v4",
            "if: always()",
            "chr-firewall-baseline-${{ github.sha }}",
        ):
            self.assertIn(required, source)
        for forbidden in (
            "ROUTEROS_PASSWORD",
            "ROUTEROS_USERNAME",
            "secrets.",
            "set +e",
            "192.168.11.",
        ):
            self.assertNotIn(forbidden, source)


if __name__ == "__main__":
    unittest.main()
