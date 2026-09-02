import json
import tempfile
import unittest
from contextlib import redirect_stdout
from io import StringIO
from pathlib import Path

from router_configuration.cli import main
from router_configuration.deployment_profile import DeploymentProfileValidator


class CliProfileInitTests(unittest.TestCase):
    def test_noninteractive_profile_init_creates_safe_10g_1g_profile(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "profile.json"
            output = StringIO()
            with redirect_stdout(output):
                rc = main([
                    "profile-init",
                    "--output", str(path),
                    "--site-name", "rd",
                    "--device-id", "rd-router-01",
                    "--management-target", "192.168.11.1",
                    "--recovery-method", "local-console",
                    "--enable-qos",
                ])
            self.assertEqual(rc, 0)
            summary = json.loads(output.getvalue())
            self.assertFalse(summary["allow_write"])
            self.assertEqual(summary["wan_weights"], {"wan-primary": 10, "wan-secondary": 1})
            profile = json.loads(path.read_text(encoding="utf-8"))
            self.assertFalse(profile["allow_write"])
            self.assertFalse(profile["intent"]["security"]["management_from_wan"])
            self.assertTrue(DeploymentProfileValidator().validate(profile).ok)

    def test_noninteractive_profile_init_requires_basic_identity_fields(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "profile.json"
            output = StringIO()
            with redirect_stdout(output):
                rc = main(["profile-init", "--output", str(path)])
            self.assertEqual(rc, 2)
            data = json.loads(output.getvalue())
            self.assertFalse(data["ok"])
            self.assertIn("--site-name", data["error"])
            self.assertFalse(path.exists())

    def test_wireguard_init_rejects_missing_secret_reference(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "profile.json"
            output = StringIO()
            with redirect_stdout(output):
                rc = main([
                    "profile-init",
                    "--output", str(path),
                    "--site-name", "rd",
                    "--device-id", "r1",
                    "--management-target", "192.168.11.1",
                    "--enable-wireguard",
                ])
            self.assertEqual(rc, 2)
            self.assertIn("secret reference", output.getvalue())
            self.assertFalse(path.exists())


if __name__ == "__main__":
    unittest.main()
