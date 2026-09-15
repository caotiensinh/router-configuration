import unittest

from router_configuration.vendors.mikrotik.normalized_operation import normalize_operation


class MikroTikNormalizedOperationTests(unittest.TestCase):
    def _payload(self):
        return {
            "schema_version": "mikrotik-normalized-operation/1",
            "vendor": "mikrotik",
            "name": "mikrotik.interface.list.generated",
            "routeros_path": "/interface",
            "action": "print",
            "mode": "read_only",
            "preferred_transport": "rest",
            "required_policies": ["read", "rest-api"],
            "features": ["interface"],
            "documentation_url": "https://manual.mikrotik.com/docs/developer-guides/rest-api/",
            "knowledge_id": "rest-api",
        }

    def test_valid_operation_contains_metadata_not_raw_cli(self):
        operation = normalize_operation(self._payload())
        self.assertEqual(operation.routeros_path, "/interface")
        self.assertEqual(operation.knowledge_id, "rest-api")

    def test_raw_cli_field_is_rejected(self):
        payload = self._payload()
        payload["command"] = "/interface print"
        with self.assertRaisesRegex(ValueError, "raw CLI"):
            normalize_operation(payload)

    def test_non_official_provenance_is_rejected(self):
        payload = self._payload()
        payload["documentation_url"] = "https://example.invalid/"
        with self.assertRaisesRegex(ValueError, "provenance"):
            normalize_operation(payload)


if __name__ == "__main__":
    unittest.main()
