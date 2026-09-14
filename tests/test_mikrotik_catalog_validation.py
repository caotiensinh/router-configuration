import unittest
from dataclasses import replace

from router_configuration.vendors.mikrotik.catalog_validation import validate_tool_catalog
from router_configuration.vendors.mikrotik.tool_registry import (
    MikroTikTransport,
    mikrotik_tool_catalog,
    tool_by_name,
)


class MikroTikCatalogValidationTests(unittest.TestCase):
    def test_current_catalog_passes_contract_validation(self):
        self.assertFalse(validate_tool_catalog(mikrotik_tool_catalog()))

    def test_continuous_rest_tool_is_rejected(self):
        original = tool_by_name("mikrotik.capture.torch")
        invalid = replace(original, preferred_transport=MikroTikTransport.REST)
        codes = {item.code for item in validate_tool_catalog((invalid,))}
        self.assertIn("continuous_rest_forbidden", codes)

    def test_non_primary_documentation_is_rejected(self):
        original = tool_by_name("mikrotik.interface.list")
        invalid = replace(original, documentation_url="https://example.invalid/manual")
        codes = {item.code for item in validate_tool_catalog((invalid,))}
        self.assertIn("non_primary_documentation", codes)


if __name__ == "__main__":
    unittest.main()
