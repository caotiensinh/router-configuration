import unittest

from router_configuration.vendors.mikrotik.knowledge_manifest import (
    bundled_knowledge_manifest,
    validate_knowledge_manifest,
)


class MikroTikKnowledgeManifestTests(unittest.TestCase):
    def test_bundled_manifest_is_offline_first_and_ai_advisory(self):
        manifest = bundled_knowledge_manifest()
        self.assertFalse(manifest.runtime_network_required)
        self.assertEqual(manifest.ai_authority, "ordering_and_explanation_only")
        self.assertTrue(manifest.structured_bundles)

    def test_non_official_primary_source_is_rejected(self):
        with self.assertRaises(ValueError):
            validate_knowledge_manifest(
                {
                    "schema_version": "mikrotik-knowledge-manifest/1",
                    "vendor": "mikrotik",
                    "runtime_network_required": False,
                    "structured_bundles": ["knowledge.json"],
                    "source_priority": ["https://example.invalid/manual"],
                    "ai_authority": "ordering_and_explanation_only",
                }
            )

    def test_runtime_network_dependency_is_rejected(self):
        with self.assertRaisesRegex(ValueError, "offline-first"):
            validate_knowledge_manifest(
                {
                    "schema_version": "mikrotik-knowledge-manifest/1",
                    "vendor": "mikrotik",
                    "runtime_network_required": True,
                    "structured_bundles": ["knowledge.json"],
                    "source_priority": ["https://manual.mikrotik.com/docs/"],
                    "ai_authority": "ordering_and_explanation_only",
                }
            )


if __name__ == "__main__":
    unittest.main()
