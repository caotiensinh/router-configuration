import json
import tempfile
import unittest
from contextlib import redirect_stdout
from io import StringIO
from pathlib import Path

from router_configuration.cli import main


ROOT = Path(__file__).resolve().parents[1]
PROFILE = ROOT / "examples" / "rd-10g-1g" / "deployment-profile.json"


class SafeSubsetIRCliTests(unittest.TestCase):
    def test_profile_compile_ir_writes_non_executable_artifact(self):
        with tempfile.TemporaryDirectory() as tmp:
            output = Path(tmp) / "intent-ir.json"
            stdout = StringIO()
            with redirect_stdout(stdout):
                rc = main(
                    [
                        "profile-compile-ir",
                        "--profile",
                        str(PROFILE),
                        "--output",
                        str(output),
                    ]
                )
            self.assertEqual(rc, 0)
            summary = json.loads(stdout.getvalue())
            self.assertTrue(summary["ok"])
            self.assertFalse(summary["vendor_commands_present"])
            self.assertFalse(summary["write_transport_present"])
            self.assertEqual(len(summary["ir_sha256"]), 64)

            artifact = json.loads(output.read_text(encoding="utf-8"))
            self.assertEqual(artifact["schema_version"], "config-safe-subset-ir/1")
            self.assertEqual(artifact["ir_sha256"], summary["ir_sha256"])
            operation = next(
                item
                for item in artifact["operations"]
                if item["operation_id"] == "routing.multiwan.capacity_weighted"
            )
            self.assertEqual(operation["attributes"]["weights"], {"wan10g": 10, "wan1g": 1})

    def test_profile_compile_ir_rejects_invalid_profile(self):
        with tempfile.TemporaryDirectory() as tmp:
            profile = json.loads(PROFILE.read_text(encoding="utf-8"))
            profile["intent"]["security"]["management_from_wan"] = True
            bad = Path(tmp) / "bad.json"
            bad.write_text(json.dumps(profile), encoding="utf-8")
            stdout = StringIO()
            with redirect_stdout(stdout):
                rc = main(["profile-compile-ir", "--profile", str(bad)])
            self.assertEqual(rc, 2)
            payload = json.loads(stdout.getvalue())
            self.assertFalse(payload["ok"])


if __name__ == "__main__":
    unittest.main()
