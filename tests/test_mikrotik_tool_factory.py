import unittest

from router_configuration.vendors.mikrotik.normalized_operation import normalize_operation
from router_configuration.vendors.mikrotik.tool_factory import generate_catalog, generate_tool


class MikroTikToolFactoryTests(unittest.TestCase):
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

    def test_factory_preserves_authoritative_metadata(self):
        operation = self._operation()
        tool = generate_tool(operation)
        self.assertEqual(tool.routeros_path, operation.routeros_path)
        self.assertEqual(tool.action, operation.action)
        self.assertFalse(tool.mutates_configuration)

    def test_generated_catalog_rejects_duplicate_names(self):
        operation = self._operation()
        with self.assertRaisesRegex(ValueError, "duplicate_tool_name"):
            generate_catalog((operation, operation))


if __name__ == "__main__":
    unittest.main()
