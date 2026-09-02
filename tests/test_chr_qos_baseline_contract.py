import importlib.util
import sys
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
CHR_DIR = ROOT / "lab" / "chr"
VALIDATOR = CHR_DIR / "verify_qos_baseline.py"
WORKFLOW = ROOT / ".github" / "workflows" / "chr-qos-baseline.yml"


def load_validator():
    sys.path.insert(0, str(CHR_DIR))
    try:
        spec = importlib.util.spec_from_file_location("verify_qos_baseline_contract", VALIDATOR)
        module = importlib.util.module_from_spec(spec)
        assert spec and spec.loader
        spec.loader.exec_module(module)
        return module
    finally:
        sys.path.pop(0)


class CHRQoSBaselineContractTests(unittest.TestCase):
    def test_fixture_renders_exact_generation_only_surface(self):
        module = load_validator()
        ir = module._build_ir()
        state = {
            "firewall": {"filter": []},
            "qos": {
                "simple_queues": [],
                "queue_tree": [],
                "queue_types": [],
            },
        }
        plan = module.render_routeros_qos(ir=ir, state=state).as_dict()
        self.assertEqual(plan["schema_version"], "routeros-qos-command-plan/1")
        self.assertEqual(plan["command_count"], 6)
        self.assertEqual(plan["classification"], "existing_dscp_only")
        self.assertEqual(plan["queue_kind"], "fq-codel")
        self.assertFalse(plan["transport_present"])
        self.assertFalse(plan["apply_available"])
        self.assertFalse(plan["write_authorized"])
        source = "\n".join(item["command"] for item in plan["commands"])
        self.assertIn('kind=fq-codel', source)
        self.assertIn('dscp=46', source)
        self.assertIn('out-interface="ether2"', source)
        self.assertIn('parent="ether2"', source)
        self.assertNotIn('change-dscp', source)

    def test_validator_uses_live_conflict_surfaces(self):
        source = VALIDATOR.read_text(encoding="utf-8")
        for required in (
            '"ip/firewall/filter"',
            '"queue/simple"',
            '"queue/tree"',
            '"queue/type"',
            '"live_conflict_surfaces_observed": True',
            '"synthetic_live_state_used": False',
        ):
            self.assertIn(required, source)

    def test_rollback_is_owned_only_and_dependency_ordered(self):
        module = load_validator()
        rollback = module._rollback_script()
        leaf = rollback.index('/queue/tree/remove [find where parent=')
        parent = rollback.index('/queue/tree/remove [find where name=')
        mangle = rollback.index('/ip/firewall/mangle/remove')
        queue_type = rollback.index('/queue/type/remove')
        self.assertLess(leaf, parent)
        self.assertLess(parent, queue_type)
        self.assertLess(mangle, queue_type)
        self.assertIn('name="routercfg-qos-lab-wan"', rollback)
        self.assertIn('comment~"^routercfg:managed:qos:"', rollback)
        self.assertIn('name="routercfg-fq-codel"', rollback)
        self.assertNotIn('/queue/tree/remove [find]\n', rollback)
        self.assertNotIn('/ip/firewall/mangle/remove [find]\n', rollback)

    def test_validator_requires_runtime_hierarchy_management_and_exact_rollback(self):
        source = VALIDATOR.read_text(encoding="utf-8")
        for required in (
            "LoopbackCHRAdmin",
            "assert_disposable_chr",
            "_execute_import_dry_run",
            "mutation._execute_import",
            "mutated_digest == baseline_digest",
            "rollback_digest != baseline_digest",
            "management_rest_reachable_after_apply",
            "voice_dscp_46_exact",
            "default_class_exact",
            "queue_hierarchy_exact",
            "fq_codel_exact",
            "rollback_digest_restored",
            '"throughput_or_latency_acceptance": False',
            '"physical_router_targeted": False',
        ):
            self.assertIn(required, source)
        for forbidden in (
            "ROUTEROS_PASSWORD",
            "ROUTEROS_USERNAME",
            "paramiko",
            "requests.",
            "192.168.11.",
        ):
            self.assertNotIn(forbidden, source)

    def test_workflow_uses_official_disposable_chr_and_preserves_evidence(self):
        source = WORKFLOW.read_text(encoding="utf-8")
        for required in (
            "ci(chr-qos):",
            'CHR_VERSION: "7.24.1"',
            "https://download.mikrotik.com/routeros/${CHR_VERSION}/chr-${CHR_VERSION}.img.zip",
            "-snapshot",
            "hostfwd=tcp:127.0.0.1:9580-:80",
            "verify_qos_baseline.py",
            "qos-baseline.json",
            "actions/upload-artifact@v4",
            "chr-qos-baseline-${{ github.sha }}",
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
