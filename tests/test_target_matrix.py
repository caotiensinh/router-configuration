import json
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
MATRIX = ROOT / "ROUTEROS_TARGET_MATRIX.json"
RAW = ROOT / "tests" / "fixtures" / "routeros_readonly_snapshot.json"
GOLDEN = ROOT / "tests" / "fixtures" / "routeros_normalized_golden.json"


class RouterOSTargetMatrixTests(unittest.TestCase):
    def setUp(self):
        self.matrix = json.loads(MATRIX.read_text(encoding="utf-8"))
        self.raw = json.loads(RAW.read_text(encoding="utf-8"))
        self.golden = json.loads(GOLDEN.read_text(encoding="utf-8"))
        self.targets = {item["id"]: item for item in self.matrix["targets"]}

    def test_synthetic_version_and_model_match_fixture_and_golden(self):
        target = self.targets["synthetic-ci-fixture"]
        raw_resource = self.raw["system_resource"]
        golden_platform = self.golden["platform"]

        self.assertEqual(target["routeros_version"], raw_resource["version"])
        self.assertEqual(target["routeros_version"], golden_platform["version"])
        self.assertEqual(target["model"], raw_resource["board-name"])
        self.assertEqual(target["model"], golden_platform["board_name"])
        self.assertEqual(target["model"], self.matrix["reference_device"]["model"])

        stable_version = self.matrix["synthetic_baseline"]["routeros_version"]
        self.assertEqual(target["routeros_version"], f"{stable_version} (stable)")

    def test_verified_targets_must_have_evidence(self):
        for target in self.matrix["targets"]:
            if "verified" in target["status"]:
                self.assertTrue(target["evidence"], target["id"])

    def test_physical_verification_cannot_precede_chr_verification(self):
        physical = self.targets["ccr2116-physical"]
        chr_target = self.targets["chr-live-v7"]
        if "verified" in physical["status"]:
            self.assertIn("verified", chr_target["status"])
            self.assertTrue(chr_target["evidence"])

    def test_current_stable_source_is_official_mikrotik(self):
        source = self.matrix["synthetic_baseline"]["source"]
        self.assertTrue(source.startswith("https://mikrotik.com/"))


if __name__ == "__main__":
    unittest.main()
