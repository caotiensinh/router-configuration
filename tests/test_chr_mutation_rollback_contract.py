import importlib.util
import sys
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "lab" / "chr" / "verify_mutation_rollback.py"


def load(path: Path, name: str):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    assert spec and spec.loader
    sys.path.insert(0, str(path.parent))
    try:
        spec.loader.exec_module(module)
    finally:
        sys.path.pop(0)
    return module


class CHRMutationRollbackContractTests(unittest.TestCase):
    def test_rollback_script_removes_owned_surfaces_in_dependency_order(self):
        module = load(SCRIPT, "verify_mutation_rollback_contract")
        commands = module._rollback_script().strip().splitlines()
        self.assertEqual(len(commands), 11)
        self.assertTrue(commands[0].startswith("/ip/firewall/mangle/remove"))
        self.assertIn("pcc-route", commands[1])
        self.assertIn("default:", commands[2])
        self.assertIn("probe:", commands[3])
        self.assertTrue(commands[4].startswith("/ip/address/remove"))
        self.assertTrue(commands[-2].startswith("/routing/table/remove"))
        self.assertTrue(commands[-1].startswith("/routing/table/remove"))

    def test_source_is_disposable_chr_only_and_fail_closed(self):
        source = SCRIPT.read_text(encoding="utf-8")
        self.assertIn("LoopbackCHRAdmin", source)
        self.assertIn("assert_disposable_chr", source)
        self.assertIn('FAIL_FILE, "this\\n"', source)
        self.assertIn("expect_success=False", source)
        self.assertIn("rollback_digest != baseline_digest", source)
        self.assertIn("_assert_managed_state_absent", source)
        self.assertIn("_assert_files_absent", source)
        self.assertIn('"production_writer_available": False', source)
        self.assertIn('"transport_exposed_to_product": False', source)
        self.assertIn('"write_authorized": False', source)
        for forbidden in (
            "ROUTEROS_PASSWORD",
            "paramiko",
            "requests.",
            "socket.",
            "subprocess",
        ):
            self.assertNotIn(forbidden, source)

    def test_expected_mutation_counts_cover_recursive_and_pcc(self):
        source = SCRIPT.read_text(encoding="utf-8")
        for expected in (
            '"pcc_mangle": 13',
            '"pcc_policy_routes": 8',
            '"recursive_probe_routes": 4',
            '"recursive_default_routes": 4',
            '"routing_tables": 2',
            '"wan_addresses": 2',
        ):
            self.assertIn(expected, source)
        self.assertIn("command_count", source)
        self.assertIn("38", source)


if __name__ == "__main__":
    unittest.main()
