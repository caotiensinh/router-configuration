import importlib.util
import sys
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
CHR_DIR = ROOT / "lab" / "chr"
VALIDATOR = CHR_DIR / "verify_pbr_baseline.py"
WORKFLOW = ROOT / ".github" / "workflows" / "chr-pbr-baseline.yml"


def load_validator():
    sys.path.insert(0, str(CHR_DIR))
    try:
        spec = importlib.util.spec_from_file_location("verify_pbr_baseline_contract", VALIDATOR)
        module = importlib.util.module_from_spec(spec)
        assert spec and spec.loader
        spec.loader.exec_module(module)
        return module
    finally:
        sys.path.pop(0)


class CHRPbrBaselineContractTests(unittest.TestCase):
    def test_fixture_uses_live_management_and_live_routing_prerequisites(self):
        source = VALIDATOR.read_text(encoding="utf-8")
        for required in (
            '"ip/address"',
            '"routing/table"',
            '"routing/rule"',
            '"management_network_source": "live_chr_ether1"',
            '"routing_tables_source": "live_chr"',
            '"routing_rules_source": "live_chr"',
            'SOURCE_CIDR = "198.51.100.0/24"',
        ):
            self.assertIn(required, source)

    def test_renderer_fixture_is_generation_only_and_uses_lookup_only_in_table(self):
        module = load_validator()
        ir = module._build_ir("10.0.2.0/24")
        state = {"routing_tables": [{"name": module.TABLE_NAME}]}
        prerequisites = {
            "schema_version": "routeros-render-prerequisites/1",
            "policy_routing": {"rules": []},
        }
        plan = module.render_routeros_pbr(
            ir=ir,
            state=state,
            prerequisites=prerequisites,
        ).as_dict()
        self.assertEqual(plan["schema_version"], "routeros-pbr-command-plan/1")
        self.assertEqual(plan["command_count"], 1)
        self.assertEqual(plan["strategy"], "routing_rules")
        self.assertFalse(plan["mangle_routing_marks"])
        self.assertFalse(plan["transport_present"])
        self.assertFalse(plan["apply_available"])
        self.assertFalse(plan["write_authorized"])
        command = plan["commands"][0]["command"]
        self.assertIn('action=lookup-only-in-table', command)
        self.assertIn('src-address="198.51.100.0/24"', command)
        self.assertIn(f'table="{module.TABLE_NAME}"', command)

    def test_lab_table_is_setup_only_and_cleanup_restores_original_baseline(self):
        source = VALIDATOR.read_text(encoding="utf-8")
        for required in (
            "_create_lab_table",
            "_remove_lab_table",
            "rollback_digest != setup_digest",
            "cleanup_digest != original_digest",
            '"routing_table_created": True',
            '"routing_table_removed": True',
            '"lab_setup_cleanup_restored": cleanup_digest == original_digest',
        ):
            self.assertIn(required, source)

    def test_rollback_owns_only_the_managed_pbr_rule(self):
        module = load_validator()
        rollback = module._rollback_script()
        self.assertEqual(
            rollback,
            '/routing/rule/remove [find where comment="routercfg:managed:pbr:lab-source-steering"]\n',
        )
        self.assertNotIn('/routing/rule/remove [find]\n', rollback)

    def test_runtime_gate_does_not_overclaim_data_plane(self):
        source = VALIDATOR.read_text(encoding="utf-8")
        for required in (
            '"lookup_only_in_table_exact": True',
            '"management_rest_reachable_after_apply": True',
            '"route_selection_data_plane_claimed": False',
            '"route_selection_data_plane_acceptance": False',
            '"physical_router_targeted": False',
            '"production_writer_available": False',
            '"write_authorized": False',
        ):
            self.assertIn(required, source)

    def test_workflow_uses_official_disposable_chr(self):
        source = WORKFLOW.read_text(encoding="utf-8")
        for required in (
            "ci(chr-pbr):",
            'CHR_VERSION: "7.24.1"',
            "https://download.mikrotik.com/routeros/${CHR_VERSION}/chr-${CHR_VERSION}.img.zip",
            "-snapshot",
            "hostfwd=tcp:127.0.0.1:9680-:80",
            "verify_pbr_baseline.py",
            "pbr-baseline.json",
            "chr-pbr-baseline-${{ github.sha }}",
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
