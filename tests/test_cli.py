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
            desired.write_text(
                json.dumps({"vpn": {"token": "new-secret"}}),
                encoding="utf-8",
            )
            actual.write_text(
                json.dumps({"vpn": {"token": "old-secret"}}),
                encoding="utf-8",
            )
            output = StringIO()
            with redirect_stdout(output):
                rc = main(
                    [
                        "plan",
                        "--desired",
                        str(desired),
                        "--actual",
                        str(actual),
                    ]
                )
            self.assertEqual(rc, 0)
            rendered = output.getvalue()
            self.assertIn("<redacted>", rendered)
            self.assertNotIn("new-secret", rendered)
            self.assertNotIn("old-secret", rendered)


if __name__ == "__main__":
    unittest.main()
