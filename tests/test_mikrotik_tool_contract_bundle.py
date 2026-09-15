import unittest

from router_configuration.vendors.mikrotik.tool_contract_bundle import build_tool_contract_bundle
from router_configuration.vendors.mikrotik.tool_registry import mikrotik_tool_catalog


class MikroTikToolContractBundleTests(unittest.TestCase):
    def test_catalog_bundle_is_deterministic_and_non_authorizing(self):
        catalog = mikrotik_tool_catalog()
        first = build_tool_contract_bundle(catalog)
        second = build_tool_contract_bundle(tuple(reversed(catalog)))
        self.assertEqual(first.catalog_sha256, second.catalog_sha256)
        self.assertEqual(first.tool_names, second.tool_names)
        self.assertFalse(first.as_dict()["write_authorized"])
        self.assertEqual(len(first.catalog_sha256), 64)


if __name__ == "__main__":
    unittest.main()
