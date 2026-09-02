import importlib.util
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
CHR_DIR = ROOT / "lab" / "chr"
VALIDATOR = CHR_DIR / "verify_vlan_baseline.py"
CORE = CHR_DIR / "vlan_baseline_core.py"
WORKFLOW = ROOT / ".github" / "workflows" / "chr-vlan-baseline.yml"


def load_validator():
    sys.path.insert(0, str(CHR_DIR))
    try:
        spec = importlib.util.spec_from_file_location("verify_vlan_baseline_contract", VALIDATOR)
        module = importlib.util.module_from_spec(spec)
        assert spec and spec.loader
        spec.loader.exec_module(module)
        return module
    finally:
        sys.path.pop(0)


class CHRVlanBaselineContractTests(unittest.TestCase):
    def test_fixture_keeps_oob_management_outside_managed_bridge(self):
        module = load_validator()
        self.assertEqual(module.OOB_MANAGEMENT, "ether1")
        self.assertEqual(module.TRUNK_PORT, "ether2")
        self.assertEqual(module.ACCESS_PORT, "ether3")
        operation = module._build_ir()["operations"][0]
        ports = {row["interface"] for row in operation["attributes"]["ports"]}
        self.assertEqual(ports, {"ether2", "ether3"})
        self.assertNotIn("ether1", ports)
        self.assertEqual(
            operation["attributes"]["activation_order"],
            "management_first_vlan_filtering_last",
        )

    def test_renderer_fixture_requires_exactly_eight_commands(self):
        module = load_validator()
        ir = module._build_ir()
        state = {
            "interfaces": [{"name": "ether1"}, {"name": "ether2"}, {"name": "ether3"}],
            "ip_addresses": [{"address": "10.0.2.15/24", "interface": "ether1"}],
        }
        prerequisites = {
            "schema_version": "routeros-render-prerequisites/1",
            "switching": {
                "bridges": [],
                "bridge_ports": [],
                "bridge_vlans": [],
                "vlan_interfaces": [],
            },
        }
        plan = module.render_routeros_vlan(
            ir=ir,
            state=state,
            prerequisites=prerequisites,
            management_path=module._management_path(),
        ).as_dict()
        self.assertEqual(plan["command_count"], 8)
        self.assertEqual(plan["commands"][-1]["command_id"], "vlan.99.activate-filtering")
        self.assertIn("vlan-filtering=yes", plan["commands"][-1]["command"])
        self.assertFalse(plan["transport_present"])
        self.assertFalse(plan["apply_available"])
        self.assertFalse(plan["write_authorized"])

    def test_runner_replaces_only_stale_fixture_count_contract(self):
        runner = VALIDATOR.read_text(encoding="utf-8")
        self.assertIn("len(commands) != 8", runner)
        self.assertIn("exactly eight generated commands", runner)
        self.assertNotIn("len(commands) != 9", runner)
        self.assertNotIn("exactly nine generated commands", runner)

    def test_core_retains_live_overlap_runtime_and_owned_rollback_checks(self):
        core = CORE.read_text(encoding="utf-8")
        for required in (
            'MGMT_ADDRESS = "192.0.2.1/24"',
            "_assert_synthetic_management_network_is_free",
            '"ip/address"',
            "target.overlaps(existing.network)",
            '"vlan_filtering_enabled": True',
            '"trunk_membership_exact": True',
            '"access_pvid_exact": True',
            '"management_vlan_interface_exact": True',
            '"oob_management_interface_untouched": True',
            '"management_rest_reachable_after_apply": True',
            "/ip/address/remove",
            "/interface/vlan/remove",
            "/interface/bridge/vlan/remove",
            "/interface/bridge/port/remove",
            "/interface/bridge/remove",
        ):
            self.assertIn(required, core)

    def test_runner_requires_exact_rollback_and_keeps_production_write_disabled(self):
        runner = VALIDATOR.read_text(encoding="utf-8")
        for required in (
            "rollback_digest != baseline_digest",
            '"rollback_digest_restored": rollback_digest == baseline_digest',
            '"in_band_vlan_data_plane_acceptance": False',
            '"physical_router_targeted": False',
            '"production_writer_available": False',
            '"transport_exposed_to_product": False',
            '"write_authorized": False',
        ):
            self.assertIn(required, runner)

    def test_workflow_uses_official_three_interface_disposable_chr(self):
        source = WORKFLOW.read_text(encoding="utf-8")
        for required in (
            "ci(chr-vlan):",
            'CHR_VERSION: "7.24.1"',
            "https://download.mikrotik.com/routeros/${CHR_VERSION}/chr-${CHR_VERSION}.img.zip",
            "-snapshot",
            "hostfwd=tcp:127.0.0.1:9880-:80",
            "id=mgmt",
            "id=trunk",
            "id=access",
            "verify_vlan_baseline.py",
            "vlan-baseline.json",
            "chr-vlan-baseline-${{ github.sha }}",
        ):
            self.assertIn(required, source)
        for forbidden in (
            "ROUTEROS_PASSWORD",
            "ROUTEROS_USERNAME",
            "secrets.",
            "192.168.11.",
        ):
            self.assertNotIn(forbidden, source)


if __name__ == "__main__":
    unittest.main()
