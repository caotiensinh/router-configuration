import copy
import json
import tempfile
import unittest
from contextlib import redirect_stdout
from io import StringIO
from pathlib import Path

from router_configuration.cli import main
from router_configuration.routeros_discovery import normalize_routeros_snapshot
from router_configuration.routeros_evidence import build_routeros_discovery_evidence


ROOT = Path(__file__).resolve().parents[1]
FIXTURE = Path(__file__).parent / "fixtures" / "routeros_readonly_snapshot.json"
PROFILE = ROOT / "examples" / "rd-10g-1g" / "deployment-profile.json"


class CliIntegrityTests(unittest.TestCase):
    def setUp(self):
        raw = json.loads(FIXTURE.read_text(encoding="utf-8"))
        self.evidence = build_routeros_discovery_evidence(
            normalize_routeros_snapshot(raw)
        )

    def test_evidence_check_accepts_generated_artifact(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "evidence.json"
            path.write_text(json.dumps(self.evidence), encoding="utf-8")
            output = StringIO()
            with redirect_stdout(output):
                rc = main(["routeros-evidence-check", "--evidence", str(path)])
            self.assertEqual(rc, 0)
            self.assertTrue(json.loads(output.getvalue())["ok"])

    def test_evidence_check_rejects_tampered_state(self):
        tampered = copy.deepcopy(self.evidence)
        tampered["normalized_state"]["interfaces"][0]["running"] = False
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "evidence.json"
            path.write_text(json.dumps(tampered), encoding="utf-8")
            output = StringIO()
            with redirect_stdout(output):
                rc = main(["routeros-evidence-check", "--evidence", str(path)])
            self.assertEqual(rc, 6)
            data = json.loads(output.getvalue())
            self.assertFalse(data["ok"])
            self.assertTrue(any("state_sha256" in item for item in data["errors"]))

    def test_preflight_blocks_tampered_evidence_before_profile_comparison(self):
        tampered = copy.deepcopy(self.evidence)
        tampered["platform"]["board_name"] = "not-the-same-summary"
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "evidence.json"
            path.write_text(json.dumps(tampered), encoding="utf-8")
            output = StringIO()
            with redirect_stdout(output):
                rc = main([
                    "routeros-preflight",
                    "--profile", str(PROFILE),
                    "--evidence", str(path),
                ])
            self.assertEqual(rc, 5)
            data = json.loads(output.getvalue())
            self.assertFalse(data["ok"])
            self.assertIn(
                "evidence.integrity",
                {item["code"] for item in data["findings"]},
            )


if __name__ == "__main__":
    unittest.main()
