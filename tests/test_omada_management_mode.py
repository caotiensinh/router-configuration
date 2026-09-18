import unittest

from router_configuration.omada_management_mode import (
    ManagementModeError,
    ManagementModeRegistry,
    build_management_mode_difference,
)


def entry(**overrides):
    values = {
        "difference_id": "gateway.portal.001",
        "product_family": "BUSINESS_GATEWAY",
        "applicability_scope": "official-business-router-mode-comparison",
        "feature": "Portal",
        "category": "CONTROLLER_ONLY_REQUIRES_ONLINE",
        "standalone_behavior": "Not available in the documented standalone scope.",
        "controller_behavior": "Configured and served by Omada Controller.",
        "controller_offline_behavior": "Existing authenticated clients continue; new authentication cannot complete.",
        "local_ui_access_when_controller_managed": False,
        "source_url": "https://support.omadanetworks.com/us/document/13103/",
        "source_locator": "Differences Between Standalone Mode and Controller Mode",
        "verification_state": "VENDOR_DOCUMENT_VERIFIED",
    }
    values.update(overrides)
    return build_management_mode_difference(**values)


class OmadaManagementModeTests(unittest.TestCase):
    def test_documented_controller_online_dependency_is_preserved(self):
        row = entry().as_dict()
        self.assertEqual(row["category"], "CONTROLLER_ONLY_REQUIRES_ONLINE")
        self.assertFalse(row["local_ui_access_when_controller_managed"])
        self.assertEqual(row["verification_state"], "VENDOR_DOCUMENT_VERIFIED")

    def test_exact_lookup_has_no_family_fallback(self):
        registry = ManagementModeRegistry([entry()])
        with self.assertRaises(ManagementModeError):
            registry.exact_lookup(
                product_family="ACCESS_POINT",
                applicability_scope="official-business-router-mode-comparison",
                feature="Portal",
            )

    def test_unknown_category_fails_closed(self):
        with self.assertRaises(ManagementModeError):
            entry(category="SOMETIMES_SUPPORTED")

    def test_nonofficial_source_is_rejected(self):
        with self.assertRaises(ManagementModeError):
            entry(source_url="https://example.com/mode")

    def test_duplicate_scope_feature_is_rejected(self):
        item = entry()
        with self.assertRaises(ManagementModeError):
            ManagementModeRegistry([item, item])


if __name__ == "__main__":
    unittest.main()
