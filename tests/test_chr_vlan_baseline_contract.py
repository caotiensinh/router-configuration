import importlib.util
import sys
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
CHR_DIR = ROOT / "lab" / "chr"
VALIDATOR = CHR_DIR / "verify_vlan_baseline.py"
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
        ir = module._build_ir()
        operation = ir["operations"][0]
        ports = {row["interface"] for row in operation["attributes"]["ports"]}
        self.assertEqual(ports, {"ether2", "ether3"})
        self.assertNotIn("ether1", ports)
        self.assertEqual(
            operation["attributes"]["activation_order"],
            "management_first_vlan_filtering_last",
        )

    def test_renderer_fixture_uses_live_state_and_live_switching_prerequisites(self):
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
        self.assertEqual(plan["schema_version"], "routeros-vlan-command-plan/1")
        self.assertEqual(plan["command_count"], 9)
        self.assertEqual(plan["activation_last_command_id"], "vlan.99.activate-filtering")
        self.assertEqual(plan["commands"][-1]["command_id"], "vlan.99.activate-filtering")
        self.assertIn("vlan-filtering=yes", plan["commands"][-1]["command"])
        self.assertFalse(plan["transport_present"])
        self.assertFalse(plan["apply_available"])
        self.assertFalse(plan["write_authorized"])

    def test_rfc5737_management_fixture_is_checked_against_live_addresses(self):
        source = VALIDATOR.read_text(encoding="utf-8")
        for required in (
            'MGMT_ADDRESS = "192.0.2.1/24"',
            "_assert_synthetic_management_network_is_free",
            '"ip/address"',
            "target.overlaps(existing.network)",
        ):
            self.assertIn(required, source)

    def test_rollback_is_reverse_dependency_order_and_owned_only(self):
        module = load_validator()
        rollback = module._rollback_script()
        address = rollback.index("/ip/address/remove")
        vlan_if = rollback.index("/interface/vlan/remove")
        membership = rollback.index("/interface/bridge/vlan/remove")
        ports = rollback.index("/interface/bridge/port/remove")
        bridge = rollback.index("/interface/bridge/remove")
        self.assertLess(address, vlan_if)
        self.assertLess(vlan_if, membership)
        self.assertLess(membership, ports)
        self.assertLess(ports, bridge)
        self.assertIn("routercfg:managed:vlan:", rollback)
        self.assertNotIn('/interface/bridge/remove [find]\n', rollback)
        self.assertNotIn('/ip/address/remove [find]\n', rollback)

    def test_runtime_requires_filtering_management_survival_and_exact_rollback(self):
        source = VALIDATOR.read_text(encoding="utf-8")
        for required in (
            '"vlan_filtering_enabled": True',
            '"trunk_membership_exact": True',
            '"access_pvid_exact": True',
            '"management_vlan_interface_exact": True',
            '"oob_management_interface_untouched": True',
            '"management_rest_reachable_after_apply": True',
            "rollback_digest != baseline_digest",
            '"rollback_digest_restored": rollback_digest == baseline_digest',
            '"in_band_vlan_data_plane_acceptance": False',
            '"physical_router_targeted": False',
            '"production_writer_available": False',
            '"write_authorized": False',
        ):
            self.assertIn(required, source)

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
