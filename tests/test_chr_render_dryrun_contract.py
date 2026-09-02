import importlib.util
import unittest
from pathlib import Path
from unittest.mock import patch


ROOT = Path(__file__).resolve().parents[1]
BUILD = ROOT / "lab" / "chr" / "build_renderer_syntax_fixture.py"
VERIFY = ROOT / "lab" / "chr" / "verify_render_dry_run.py"
WORKFLOW = ROOT / ".github" / "workflows" / "chr-render-dryrun.yml"
CLI = ROOT / "src" / "router_configuration" / "cli.py"


def load(path: Path, name: str):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    assert spec and spec.loader
    spec.loader.exec_module(module)
    return module


class CHRRenderDryRunContractTests(unittest.TestCase):
    def test_syntax_fixture_exercises_all_current_command_templates(self):
        module = load(BUILD, "build_renderer_syntax_fixture")
        plan = module.build_syntax_fixture()
        self.assertFalse(plan["complete"])
        self.assertEqual(len(plan["blocked_operations"]), 1)
        blocker = plan["blocked_operations"][0]
        self.assertEqual(blocker["operation_id"], "routing.multiwan.capacity_weighted")
        self.assertIn("PCC", blocker["reason"])
        self.assertEqual(blocker["required_inputs"], [])
        self.assertEqual(len(plan["commands"]), 17)
        sections = {item["section"] for item in plan["commands"]}
        self.assertEqual(
            sections,
            {
                "interface_list",
                "interface_list_member",
                "ip_address",
                "routing_table",
                "ip_route",
            },
        )
        self.assertEqual(plan["secret_references"], [])
        self.assertFalse(plan["transport_present"])
        self.assertFalse(plan["apply_available"])
        self.assertFalse(plan["write_authorized"])

    def test_lab_admin_refuses_non_loopback_or_https_target(self):
        module = load(VERIFY, "verify_render_dry_run")
        self.assertIsInstance(module.LoopbackCHRAdmin("http://127.0.0.1:9180"), module.LoopbackCHRAdmin)
        for target in (
            "https://127.0.0.1:9443",
            "http://192.0.2.10:9180",
            "http://example.com",
            "http://127.0.0.1:9180/rest",
        ):
            with self.assertRaises(module.CHRRenderDryRunError):
                module.LoopbackCHRAdmin(target)

    def test_configuration_digest_is_deterministic(self):
        module = load(VERIFY, "verify_render_dry_run_digest")
        first = {
            "interface_lists": [{"name": "a"}],
            "interface_list_members": [],
            "ip_addresses": [],
            "routing_tables": [{"name": "main", "fib": "true"}],
            "ip_routes": [],
        }
        second = {
            "ip_routes": [],
            "routing_tables": [{"fib": "true", "name": "main"}],
            "ip_addresses": [],
            "interface_list_members": [],
            "interface_lists": [{"name": "a"}],
        }
        self.assertEqual(module._canonical_digest(first), module._canonical_digest(second))

    def test_verdict_file_parser_is_fail_closed(self):
        module = load(VERIFY, "verify_render_dry_run_verdict_file")
        self.assertEqual(module._parse_verdict_contents("OK"), (False, ""))
        captured, detail = module._parse_verdict_contents(
            "ERROR|Script Error: bad command name this (line 1 column 1)"
        )
        self.assertTrue(captured)
        self.assertIn("bad command name this", detail)
        for contents in ("PENDING", "*12", "ERROR|", "", "unknown"):
            with self.assertRaises(module.CHRRenderDryRunError):
                module._parse_verdict_contents(contents)

    def test_async_verdict_poll_waits_until_routeros_job_finishes(self):
        module = load(VERIFY, "verify_render_dry_run_poll")
        admin = object()
        with patch.object(
            module,
            "_read_file_contents",
            side_effect=["PENDING", "PENDING", "OK"],
        ) as read_contents:
            with patch.object(module.time, "sleep", return_value=None) as sleep:
                result = module._wait_for_verdict(
                    admin,
                    "routercfg-render-verdict.txt",
                    timeout_seconds=1.0,
                    poll_interval_seconds=0.001,
                )
        self.assertEqual(result, "OK")
        self.assertEqual(read_contents.call_count, 3)
        self.assertEqual(sleep.call_count, 2)

    def test_validator_covers_every_failover_mutation_surface(self):
        source = VERIFY.read_text(encoding="utf-8")
        for surface in (
            '"interface/list"',
            '"interface/list/member"',
            '"ip/address"',
            '"routing/table"',
            '"ip/route"',
        ):
            self.assertIn(surface, source)
        self.assertIn('row.get("dynamic")', source)
        self.assertIn('"snapshot_surfaces"', source)

    def test_validator_uses_temporary_file_verdict_and_documented_negative_control(self):
        source = VERIFY.read_text(encoding="utf-8")
        cli_source = CLI.read_text(encoding="utf-8")
        self.assertNotIn("verify_render_dry_run", cli_source)
        self.assertIn("verbose=yes dry-run", source)
        self.assertIn(":onerror e in={", source)
        self.assertIn("routercfg-render-verdict.txt", source)
        self.assertIn('contents=("ERROR|" . [:tostr $e])', source)
        self.assertIn('contents="OK"', source)
        self.assertIn("_parse_verdict_contents", source)
        self.assertIn("_wait_for_verdict", source)
        self.assertIn("time.monotonic", source)
        self.assertNotIn("_extract_execute_verdict", source)
        self.assertIn('_create_text_file(admin, invalid_name, "this\\n")', source)
        self.assertIn("temporary_routeros_file", source)
        self.assertIn("_assert_files_absent", source)
        self.assertIn("negative-control RouterOS script unexpectedly passed dry-run", source)
        self.assertIn("configuration changed during import dry-run validation", source)
        self.assertIn('"production_writer_available": False', source)
        self.assertIn('"write_authorized": False', source)

    def test_workflow_is_snapshot_only_and_trigger_is_separate_from_populated_acceptance(self):
        source = WORKFLOW.read_text(encoding="utf-8")
        self.assertIn("ci(chr-render):", source)
        self.assertIn("-snapshot", source)
        self.assertIn("build_renderer_syntax_fixture.py", source)
        self.assertIn("verify_render_dry_run_chunked.py", source)
        self.assertIn("ether1", source)
        self.assertIn("ether2", source)
        self.assertIn("ether3", source)
        self.assertNotIn("ROUTEROS_PASSWORD", source)


if __name__ == "__main__":
    unittest.main()
