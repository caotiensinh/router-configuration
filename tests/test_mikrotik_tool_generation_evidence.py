import unittest

from router_configuration.vendors.mikrotik.normalized_operation import normalize_operation
from router_configuration.vendors.mikrotik.tool_factory import generate_catalog
from router_configuration.vendors.mikrotik.tool_generation_evidence import build_generation_evidence


class MikroTikToolGenerationEvidenceTests(unittest.TestCase):
    def _operation(self, name="mikrotik.generated.interface.list"):
        return normalize_operation(
            {
                "schema_version": "mikrotik-normalized-operation/1",
                "vendor": "mikrotik",
                "name": name,
                "routeros_path": "/interface",
                "action": "print",
                "mode": "read_only",
                "preferred_transport": "rest",
                "required_policies": ["read", "rest-api"],
                "features": ["interface"],
                "documentation_url": "https://manual.mikrotik.com/docs/developer-guides/rest-api/",
                "knowledge_id": "rest-api",
            }
        )

    def test_generation_evidence_binds_input_output_and_knowledge(self):
        operation = self._operation()
        tools = generate_catalog((operation,))
        evidence = build_generation_evidence(
            operations=(operation,),
            tools=tools,
            knowledge_sha256="a" * 64,
        )
        self.assertEqual(len(evidence.normalized_input_sha256), 64)
        self.assertEqual(len(evidence.generated_catalog_sha256), 64)
        self.assertFalse(evidence.as_dict()["write_authorized"])

    def test_mismatched_generated_identity_is_rejected(self):
        first = self._operation("mikrotik.generated.first")
        second = self._operation("mikrotik.generated.second")
        with self.assertRaisesRegex(ValueError, "exactly match"):
            build_generation_evidence(
                operations=(first,),
                tools=generate_catalog((second,)),
                knowledge_sha256="b" * 64,
            )


if __name__ == "__main__":
    unittest.main()
