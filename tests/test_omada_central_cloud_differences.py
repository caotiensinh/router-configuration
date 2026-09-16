import json
import unittest
from pathlib import Path

ROOT = Path(__file__).parents[1]

class OmadaCentralCloudDifferencesTests(unittest.TestCase):
    def test_controller_models_keep_service_location_ownership_and_tier_separate(self):
        data = json.loads((ROOT / "artifacts" / "OMADA_CENTRAL_CLOUD_DIFFERENCES_SCHEMA.json").read_text(encoding="utf-8"))
        self.assertEqual(data["task"], "7.14")
        self.assertIn("on_premises_hybrid_cloud", data["deployment_models"])
        self.assertIn("omada_cloud_standard", data["deployment_models"])
        self.assertIn("omada_cloud_essentials", data["deployment_models"])
        self.assertTrue(data["differences"]["cloud_access_is_not_same_as_cloud_based_controller"])
        self.assertTrue(data["differences"]["cloud_essentials_does_not_support_msp_mode"])
        self.assertEqual(data["safety"]["unknown_feature_parity"], "NOT_SUPPORTED_UNVERIFIED")
        kb=(ROOT/"knowledge"/"OMADA_CENTRAL_CLOUD_DIFFERENCES_KB.md").read_text(encoding="utf-8")
        self.assertIn("Cloud Access", kb)
        self.assertIn("service location", kb)
        self.assertIn("MSP Mode", kb)

if __name__ == "__main__":
    unittest.main()
