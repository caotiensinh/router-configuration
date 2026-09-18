import unittest

from router_configuration.omada_openapi_registry import (
    OpenApiOperationRegistry,
    OpenApiRegistryError,
    build_openapi_operation,
)


SOURCE_SHA = "c" * 64


def operation(**overrides):
    values = {
        "operation_id": "fixture.create-site",
        "semantic_action": "CREATE_SITE",
        "http_method": "POST",
        "endpoint_path": "/verified-fixture/create-site",
        "controller_platform": "SOFTWARE_CONTROLLER",
        "controller_version": "6.3.0.45",
        "auth_mode": "CLIENT_CREDENTIALS",
        "source_url": "https://support.omadanetworks.com/en/document/109315/",
        "source_sha256": SOURCE_SHA,
        "source_locator": "Create new site / Online API Document binding",
        "verification_state": "VENDOR_DOCUMENT_VERIFIED",
    }
    values.update(overrides)
    return build_openapi_operation(**values)


class OmadaOpenApiRegistryTests(unittest.TestCase):
    def test_exact_operation_is_registered_non_executable(self):
        registry = OpenApiOperationRegistry([operation()])
        row = registry.exact_lookup(
            "fixture.create-site",
            controller_platform="SOFTWARE_CONTROLLER",
            controller_version="6.3.0.45",
        ).as_dict()
        self.assertEqual(row["http_method"], "POST")
        self.assertTrue(row["requires_access_token"])
        self.assertFalse(row["executable"])

    def test_platform_or_version_fallback_is_forbidden(self):
        registry = OpenApiOperationRegistry([operation()])
        with self.assertRaises(OpenApiRegistryError):
            registry.exact_lookup(
                "fixture.create-site",
                controller_platform="HARDWARE_CONTROLLER",
                controller_version="6.3.0.45",
            )

    def test_placeholder_endpoint_is_rejected(self):
        with self.assertRaises(OpenApiRegistryError):
            operation(endpoint_path="/api/{siteId}")

    def test_unverified_operation_is_rejected(self):
        with self.assertRaises(OpenApiRegistryError):
            operation(verification_state="AI_INFERRED")

    def test_duplicate_exact_scope_is_rejected(self):
        item = operation()
        with self.assertRaises(OpenApiRegistryError):
            OpenApiOperationRegistry([item, item])


if __name__ == "__main__":
    unittest.main()
