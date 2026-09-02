import json
import tempfile
import unittest
from contextlib import redirect_stdout
from io import StringIO
from pathlib import Path

from router_configuration.cli import main


class CliTests(unittest.TestCase):
    def test_multiwan_command(self):
        output = StringIO()
        with redirect_stdout(output):
            rc = main(["multiwan", "--wan", "wan10g=10000", "--wan", "wan1g=1000"])
        self.assertEqual(rc, 0)
        data = json.loads(output.getvalue())
        self.assertEqual(data["weights"], {"wan10g": 10, "wan1g": 1})

    def test_plan_redacts_secret_paths(self):
        with tempfile.TemporaryDirectory() as tmp:
            desired = Path(tmp) / "desired.json"
            actual = Path(tmp) / "actual.json"
            desired.write_text(json.dumps({"vpn": {"token": "new-secret"}}), encoding="utf-8")
            actual.write_text(json.dumps({"vpn": {"token": "old-secret"}}), encoding="utf-8")
            output = StringIO()
            with redirect_stdout(output):
                rc = main(["plan", "--desired", str(desired), "--actual", str(actual)])
            self.assertEqual(rc, 0)
            rendered = output.getvalue()
            self.assertIn("<redacted>", rendered)
            self.assertNotIn("new-secret", rendered)
            self.assertNotIn("old-secret", rendered)

    def test_profile_check_is_read_only_and_reports_weights(self):
        with tempfile.TemporaryDirectory() as tmp:
            profile = Path(tmp) / "profile.json"
            profile.write_text(
                json.dumps({
                    "schema_version": "1.0",
                    "site_name": "rd",
                    "environment": "production",
                    "operator_mode": "guided",
                    "allow_write": False,
                    "device": {"id": "r1", "vendor": "mikrotik", "management_target": "192.168.11.1"},
                    "topology": {
                        "wans": [
                            {"name": "wan10g", "interface": "sfp1", "capacity_mbps": 10000},
                            {"name": "wan1g", "interface": "ether1", "capacity_mbps": 1000},
                        ],
                        "core": {"interface": "sfp2", "capacity_mbps": 10000},
                    },
                }),
                encoding="utf-8",
            )
            output = StringIO()
            with redirect_stdout(output):
                rc = main(["profile-check", "--profile", str(profile)])
            self.assertEqual(rc, 0)
            data = json.loads(output.getvalue())
            self.assertTrue(data["ok"])
            self.assertFalse(data["deployment"]["allow_write"])
            self.assertEqual(data["wan_weights"], {"wan10g": 10, "wan1g": 1})

    def test_workflow_command_explains_failure_action(self):
        output = StringIO()
        with redirect_stdout(output):
            rc = main(["workflow", "--stage", "preflight"])
        self.assertEqual(rc, 0)
        data = json.loads(output.getvalue())
        self.assertEqual(data["stage"], "preflight")
        self.assertTrue(data["failure_action"])


if __name__ == "__main__":
    unittest.main()
