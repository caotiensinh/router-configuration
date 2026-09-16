import unittest

from router_configuration.vendors.cisco.acceptance_dispatch_request import (
    CiscoAcceptanceDispatchRequestError,
    build_dispatch_request,
    validate_dispatch_request,
)


class CiscoAcceptanceDispatchRequestTests(unittest.TestCase):
    def request(self):
        return build_dispatch_request(
            request_id="ACC-C03-20260916-001",
            stage="c03",
            target_ref="feat/cisco-iosxe-router-switch-domain-20260915",
            expected_source_sha="1" * 40,
            requested_by_ref="human-master:caotiensinh",
            requested_by_attestation_sha256="2" * 64,
        )

    def test_build_is_deterministic_and_readonly(self):
        first = self.request()
        second = self.request()
        self.assertEqual(first, second)
        self.assertEqual(first["workflow_file"], "cisco-netconf-live-readonly.yml")
        self.assertTrue(first["read_only_required"])
        self.assertFalse(first["production_write_authorized"])
        self.assertFalse(first["physical_device_verified"])
        self.assertEqual(len(first["request_sha256"]), 64)

    def test_c04_is_allowed_but_write_stages_are_not(self):
        item = build_dispatch_request(
            request_id="ACC-C04-001",
            stage="c04",
            target_ref="feat/cisco-iosxe-router-switch-domain-20260915",
            expected_source_sha="3" * 40,
            requested_by_ref="human-master:caotiensinh",
            requested_by_attestation_sha256="4" * 64,
        )
        self.assertEqual(item["workflow_file"], "cisco-restconf-live-readonly.yml")

        raw = dict(self.request())
        raw.pop("workflow_file")
        raw.pop("physical_device_verified")
        raw["stage"] = "c12"
        with self.assertRaisesRegex(CiscoAcceptanceDispatchRequestError, "allowlist"):
            validate_dispatch_request(raw)

    def test_tamper_unknown_field_or_write_authority_fails_closed(self):
        raw = dict(self.request())
        raw.pop("workflow_file")
        raw.pop("physical_device_verified")
        raw["expected_source_sha"] = "9" * 40
        with self.assertRaisesRegex(CiscoAcceptanceDispatchRequestError, "digest mismatch"):
            validate_dispatch_request(raw)

        raw = dict(self.request())
        raw.pop("workflow_file")
        raw.pop("physical_device_verified")
        raw["extra"] = True
        with self.assertRaisesRegex(CiscoAcceptanceDispatchRequestError, "closed schema"):
            validate_dispatch_request(raw)

        raw = dict(self.request())
        raw.pop("workflow_file")
        raw.pop("physical_device_verified")
        raw["production_write_authorized"] = True
        with self.assertRaises(CiscoAcceptanceDispatchRequestError):
            validate_dispatch_request(raw)


if __name__ == "__main__":
    unittest.main()
