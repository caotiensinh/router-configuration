import json
import tempfile
import unittest
from contextlib import redirect_stdout
from io import StringIO
from pathlib import Path
from unittest.mock import patch

from router_configuration.routeros_discovery import normalize_routeros_snapshot
from router_configuration.routeros_evidence import build_routeros_discovery_evidence
from router_configuration.routerctl import main
from router_configuration.safe_subset_ir import SafeSubsetCompiler


ROOT = Path(__file__).resolve().parents[1]
PROFILE = ROOT / "examples" / "rd-10g-1g" / "deployment-profile.json"
RAW = ROOT / "tests" / "fixtures" / "routeros_readonly_snapshot.json"
ROUTERCTL = ROOT / "src" / "router_configuration" / "routerctl.py"


class RouterctlDispatcherTests(unittest.TestCase):
    def test_routeros_render_generates_offline_plan_and_script(self):
        profile = json.loads(PROFILE.read_text(encoding="utf-8"))
        ir = SafeSubsetCompiler().compile(profile).as_dict()
        raw = json.loads(RAW.read_text(encoding="utf-8"))
        evidence = build_routeros_discovery_evidence(normalize_routeros_snapshot(raw))

        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            profile_path = tmp_path / "profile.json"
            ir_path = tmp_path / "ir.json"
            evidence_path = tmp_path / "evidence.json"
            output_path = tmp_path / "render.json"
            script_path = tmp_path / "render.rsc"
            profile_path.write_text(json.dumps(profile), encoding="utf-8")
            ir_path.write_text(json.dumps(ir), encoding="utf-8")
            evidence_path.write_text(json.dumps(evidence), encoding="utf-8")

            stdout = StringIO()
            with redirect_stdout(stdout):
                rc = main([
                    "routeros-render",
                    "--profile", str(profile_path),
                    "--ir", str(ir_path),
                    "--evidence", str(evidence_path),
                    "--output", str(output_path),
                    "--script-output", str(script_path),
                ])

            self.assertEqual(rc, 0, stdout.getvalue())
            summary = json.loads(stdout.getvalue())
            self.assertTrue(summary["ok"])
            self.assertFalse(summary["generation_complete"])
            self.assertEqual(summary["command_count"], 12)
            self.assertTrue(summary["blocked_operations"])
            self.assertFalse(summary["transport_present"])
            self.assertFalse(summary["apply_available"])
            self.assertFalse(summary["write_authorized"])

            payload = json.loads(output_path.read_text(encoding="utf-8"))
            self.assertTrue(payload["ok"])
            self.assertEqual(payload["render_plan"]["claim"], "generation_partial")
            self.assertFalse(payload["render_plan"]["secrets_resolved"])
            qos = payload["render_plan"]["generation_extensions"]["qos"]
            self.assertEqual(qos["command_count"], 7)
            self.assertFalse(qos["default_traffic_marked"])
            script = script_path.read_text(encoding="utf-8")
            self.assertEqual(len([line for line in script.splitlines() if line.strip()]), 12)
            self.assertIn("dscp=46", script)
            self.assertIn("kind=fq-codel", script)
            self.assertNotIn("password", script.lower())
            self.assertNotIn("private-key", script.lower())

    def test_routeros_render_blocks_tampered_ir_without_script(self):
        profile = json.loads(PROFILE.read_text(encoding="utf-8"))
        ir = SafeSubsetCompiler().compile(profile).as_dict()
        ir["device_id"] = "tampered-device"
        raw = json.loads(RAW.read_text(encoding="utf-8"))
        evidence = build_routeros_discovery_evidence(normalize_routeros_snapshot(raw))

        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            profile_path = tmp_path / "profile.json"
            ir_path = tmp_path / "ir.json"
            evidence_path = tmp_path / "evidence.json"
            output_path = tmp_path / "render.json"
            script_path = tmp_path / "render.rsc"
            profile_path.write_text(json.dumps(profile), encoding="utf-8")
            ir_path.write_text(json.dumps(ir), encoding="utf-8")
            evidence_path.write_text(json.dumps(evidence), encoding="utf-8")

            stdout = StringIO()
            with redirect_stdout(stdout):
                rc = main([
                    "routeros-render",
                    "--profile", str(profile_path),
                    "--ir", str(ir_path),
                    "--evidence", str(evidence_path),
                    "--output", str(output_path),
                    "--script-output", str(script_path),
                ])

            self.assertEqual(rc, 7)
            self.assertTrue(output_path.exists())
            self.assertFalse(script_path.exists())
            payload = json.loads(output_path.read_text(encoding="utf-8"))
            self.assertFalse(payload["ok"])
            self.assertTrue(any("IR" in error for error in payload["errors"]))

    def test_other_routerctl_commands_delegate_unchanged(self):
        with patch("router_configuration.routerctl.legacy_main", return_value=23) as legacy:
            rc = main(["progress", "--file", "x.json"])
        self.assertEqual(rc, 23)
        legacy.assert_called_once_with(["progress", "--file", "x.json"])

    def test_routeros_render_surface_has_no_live_or_apply_arguments(self):
        source = ROUTERCTL.read_text(encoding="utf-8")
        for forbidden in (
            'add_argument("--url"',
            'add_argument("--username"',
            'add_argument("--password',
            'add_argument("--apply"',
            'add_argument("--write"',
            "RouterOSRestClient",
            "ROUTEROS_PASSWORD",
        ):
            self.assertNotIn(forbidden, source)
        self.assertIn('"transport_present": False', source)
        self.assertIn('"apply_available": False', source)
        self.assertIn('"write_authorized": False', source)


if __name__ == "__main__":
    unittest.main()
