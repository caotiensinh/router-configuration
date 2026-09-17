import unittest
from urllib.parse import urlparse

from router_configuration.vendors.yamaha import (
    YamahaOfflineKnowledge,
    assess_read_only_candidate,
    normalize_firmware,
    normalize_model,
)


class YamahaRTX3510DomainTests(unittest.TestCase):
    def test_exact_model_and_current_firmware_are_read_only_candidate(self) -> None:
        decision = assess_read_only_candidate("RTX3510", "Rev.23.01.03")
        self.assertEqual(decision.status, "DOCUMENTED_READ_ONLY_CANDIDATE")
        self.assertTrue(decision.read_only_candidate)
        self.assertEqual(decision.normalized_model, "RTX3510")
        self.assertEqual(decision.normalized_firmware, "23.01.03")
        self.assertFalse(decision.write_authorized)
        self.assertFalse(decision.physical_device_verified)

    def test_firmware_prefix_normalization_is_deterministic(self) -> None:
        self.assertEqual(normalize_firmware("Rev.23.01.03"), "23.01.03")
        self.assertEqual(normalize_firmware("23.01.03"), "23.01.03")
        self.assertIsNone(normalize_firmware("Rev.23.1.3"))
        self.assertIsNone(normalize_firmware("unknown"))

    def test_model_normalization_does_not_cross_admit_other_rtx_models(self) -> None:
        self.assertEqual(normalize_model("RTX-3510"), "RTX3510")
        other = assess_read_only_candidate("RTX1300", "Rev.23.01.03")
        self.assertEqual(other.status, "UNVERIFIED_PLATFORM")
        self.assertFalse(other.read_only_candidate)
        self.assertEqual(other.documentation_source_ids, ())

    def test_non_admitted_firmware_fails_closed(self) -> None:
        for version in ("Rev.23.01.01", "Rev.23.01.02", "Rev.23.01.04", "unknown"):
            with self.subTest(version=version):
                decision = assess_read_only_candidate("RTX3510", version)
                self.assertEqual(decision.status, "UNVERIFIED_VERSION")
                self.assertFalse(decision.read_only_candidate)
                self.assertFalse(decision.write_authorized)
                self.assertFalse(decision.physical_device_verified)

    def test_offline_manifest_uses_only_official_yamaha_hosts(self) -> None:
        knowledge = YamahaOfflineKnowledge()
        self.assertGreaterEqual(len(knowledge.source_ids()), 8)
        allowed_hosts = {
            "network.yamaha.com",
            "rtpro.yamaha.co.jp",
            "www.rtpro.yamaha.co.jp",
        }
        for source_id in knowledge.source_ids():
            source = knowledge.source(source_id)
            self.assertEqual(source.authority, "official_yamaha")
            parsed = urlparse(source.url)
            self.assertEqual(parsed.scheme, "https")
            self.assertIn(parsed.hostname, allowed_hosts)

    def test_manifest_contains_exact_model_firmware_sources(self) -> None:
        ids = set(YamahaOfflineKnowledge().source_ids())
        self.assertIn("YAMAHA-RTX3510-SPEC", ids)
        self.assertIn("YAMAHA-RTX3510-FIRMWARE", ids)
        self.assertIn("YAMAHA-RTX3510-RELNOTE-23.01.03", ids)
        self.assertIn("YAMAHA-RTX-CMDREF", ids)

    def test_platform_matrix_retains_fail_closed_boundaries(self) -> None:
        matrix = YamahaOfflineKnowledge().platform_matrix
        self.assertEqual(len(matrix["models"]), 1)
        model = matrix["models"][0]
        self.assertEqual(model["model"], "RTX3510")
        self.assertEqual(model["admitted_firmware"], ["23.01.03"])

        boundaries = matrix["boundaries"]
        self.assertFalse(boundaries["other_rtx_models_in_scope"])
        self.assertFalse(boundaries["production_write_authorized"])
        self.assertFalse(boundaries["physical_device_verified"])
        self.assertFalse(boundaries["automatic_feature_support_inference"])

    def test_offline_knowledge_digest_is_deterministic(self) -> None:
        first = YamahaOfflineKnowledge().digest_sha256
        second = YamahaOfflineKnowledge().digest_sha256
        self.assertEqual(first, second)
        self.assertEqual(len(first), 64)


if __name__ == "__main__":
    unittest.main()
