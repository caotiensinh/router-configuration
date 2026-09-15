import unittest
from dataclasses import replace

from router_configuration.vendors.cisco.desired_state import render_interface_description
from router_configuration.vendors.cisco.validation_approval import (
    CiscoValidationApprovalError,
    build_approval_binding,
    validate_approval_fingerprint,
    validate_desired_state_render,
)


MODULES = {"Cisco-IOS-XE-native"}
CAPABILITIES = {"urn:ietf:params:netconf:capability:candidate:1.0"}
SCHEMA_DIGEST = "b" * 64
PRE_STATE = "a" * 64


class CiscoValidationApprovalTests(unittest.TestCase):
    def _render(self, **overrides):
        params = {
            "model": "C9300-24T",
            "iosxe_version": "17.18.1a",
            "schema_inventory_digest_sha256": SCHEMA_DIGEST,
            "observed_modules": MODULES,
            "netconf_capabilities": CAPABILITIES,
            "interface_name": "1/0/1",
            "description": "uplink-core-01",
        }
        params.update(overrides)
        return render_interface_description(**params)

    def _validation(self, render=None, **overrides):
        kwargs = {
            "target_id": "sw-core-01",
            "pre_state_sha256": PRE_STATE,
            "render": render or self._render(),
        }
        kwargs.update(overrides)
        return validate_desired_state_render(**kwargs)

    def _binding(self, render=None, validation=None, **overrides):
        artifact = render or self._render()
        attestation = validation or self._validation(artifact)
        kwargs = {
            "change_id": "CHG-20260915-001",
            "target_id": "sw-core-01",
            "pre_state_sha256": PRE_STATE,
            "render": artifact,
            "validation": attestation,
        }
        kwargs.update(overrides)
        return build_approval_binding(**kwargs)

    def test_validation_is_deterministic_and_pre_write(self):
        render = self._render()
        first = self._validation(render)
        second = self._validation(render)
        self.assertEqual(first, second)
        self.assertTrue(first.passed)
        self.assertEqual(first.findings, ())
        self.assertEqual(len(first.validation_sha256), 64)
        self.assertFalse(first.c08_complete)
        self.assertFalse(first.write_authorized)
        self.assertFalse(first.production_write_authorized)

    def test_validation_binds_target_pre_state_and_c07_digests(self):
        render = self._render()
        attestation = self._validation(render)
        self.assertEqual(attestation.target_id, "sw-core-01")
        self.assertEqual(attestation.pre_state_sha256, PRE_STATE)
        self.assertEqual(attestation.payload_digest_sha256, render.payload_digest_sha256)
        self.assertEqual(attestation.schema_inventory_digest_sha256, render.schema_inventory_digest_sha256)
        self.assertEqual(attestation.catalog_digest_sha256, render.catalog_digest_sha256)

    def test_tampered_payload_is_rejected(self):
        render = self._render()
        tampered = replace(render, payload_xml=render.payload_xml.replace("uplink-core-01", "other"))
        with self.assertRaisesRegex(CiscoValidationApprovalError, "payload digest mismatch"):
            self._validation(tampered)

    def test_extra_xml_structure_is_rejected_even_with_matching_digest(self):
        render = self._render()
        payload = render.payload_xml.replace(
            "</GigabitEthernet>",
            "<shutdown /></GigabitEthernet>",
        )
        import hashlib

        tampered = replace(
            render,
            payload_xml=payload,
            payload_digest_sha256=hashlib.sha256(payload.encode("utf-8")).hexdigest(),
        )
        with self.assertRaisesRegex(CiscoValidationApprovalError, "structure differs"):
            self._validation(tampered)

    def test_stale_catalog_is_rejected(self):
        render = replace(self._render(), catalog_digest_sha256="c" * 64)
        with self.assertRaisesRegex(CiscoValidationApprovalError, "stale or different catalog"):
            self._validation(render)

    def test_pre_write_boundary_must_remain_closed(self):
        render = replace(self._render(), apply_authorized=True)
        with self.assertRaisesRegex(CiscoValidationApprovalError, "safety boundary"):
            self._validation(render)

    def test_invalid_target_and_pre_state_are_rejected(self):
        with self.assertRaises(CiscoValidationApprovalError):
            self._validation(target_id="sw core 01")
        with self.assertRaisesRegex(CiscoValidationApprovalError, "SHA-256"):
            self._validation(pre_state_sha256="not-a-digest")

    def test_approval_binding_is_deterministic_and_never_authorizes(self):
        render = self._render()
        validation = self._validation(render)
        first = self._binding(render, validation)
        second = self._binding(render, validation)
        self.assertEqual(first, second)
        self.assertEqual(len(first.approval_sha256), 64)
        self.assertFalse(first.approval_bound)
        self.assertFalse(first.human_approved)
        self.assertFalse(first.c08_complete)
        self.assertFalse(first.apply_authorized)
        self.assertFalse(first.write_authorized)
        self.assertFalse(first.production_write_authorized)
        validate_approval_fingerprint(first, first.approval_sha256)

    def test_approval_changes_when_target_or_pre_state_changes(self):
        render = self._render()
        validation_a = self._validation(render)
        binding_a = self._binding(render, validation_a)

        validation_b = self._validation(render, target_id="sw-core-02")
        binding_b = self._binding(
            render,
            validation_b,
            target_id="sw-core-02",
        )
        self.assertNotEqual(binding_a.approval_sha256, binding_b.approval_sha256)

        pre_b = "d" * 64
        validation_c = self._validation(render, pre_state_sha256=pre_b)
        binding_c = self._binding(
            render,
            validation_c,
            pre_state_sha256=pre_b,
        )
        self.assertNotEqual(binding_a.approval_sha256, binding_c.approval_sha256)

    def test_validation_for_different_render_cannot_be_reused(self):
        original = self._render(description="uplink-a")
        validation = self._validation(original)
        changed = self._render(description="uplink-b")
        with self.assertRaisesRegex(CiscoValidationApprovalError, "stale or belongs"):
            self._binding(changed, validation)

    def test_stale_approval_fingerprint_is_rejected(self):
        binding = self._binding()
        with self.assertRaisesRegex(CiscoValidationApprovalError, "stale or belongs"):
            validate_approval_fingerprint(binding, "f" * 64)

    def test_router_26_binding_preserves_platform_identity(self):
        render = self._render(model="C8000V", iosxe_version="26.1.1")
        validation = self._validation(render, target_id="edge-rtr-01")
        binding = self._binding(
            render,
            validation,
            target_id="edge-rtr-01",
        )
        self.assertEqual(binding.documentation_train, "26")
        self.assertEqual(binding.platform_family, "Catalyst 8000V")
        self.assertEqual(binding.role, "router")


if __name__ == "__main__":
    unittest.main()
