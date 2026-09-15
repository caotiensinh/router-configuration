import hashlib
import unittest
from dataclasses import replace

from router_configuration.vendors.cisco.desired_state import render_interface_shutdown
from router_configuration.vendors.cisco.validation_approval import (
    CiscoValidationApprovalError,
    build_approval_binding,
    validate_desired_state_render,
)

MODULES = {"Cisco-IOS-XE-native"}
CAPABILITIES = {"urn:ietf:params:netconf:capability:candidate:1.0"}
SCHEMA_DIGEST = "b" * 64
PRE_STATE = "a" * 64


class CiscoShutdownValidationIntegrationTests(unittest.TestCase):
    def _render(self, **overrides):
        params = {
            "model": "C9300-24T",
            "iosxe_version": "17.18.1a",
            "schema_inventory_digest_sha256": SCHEMA_DIGEST,
            "observed_modules": MODULES,
            "netconf_capabilities": CAPABILITIES,
            "interface_name": "1/0/1",
        }
        params.update(overrides)
        return render_interface_shutdown(**params)

    def test_shutdown_render_validates_and_binds_without_authorizing(self):
        render = self._render()
        validation = validate_desired_state_render(
            target_id="sw-core-01",
            pre_state_sha256=PRE_STATE,
            render=render,
        )
        binding = build_approval_binding(
            change_id="CHG-SHUTDOWN-001",
            target_id="sw-core-01",
            pre_state_sha256=PRE_STATE,
            render=render,
            validation=validation,
        )
        self.assertEqual(validation.feature_id, "interface.shutdown.set")
        self.assertEqual(binding.feature_id, "interface.shutdown.set")
        self.assertFalse(validation.c08_complete)
        self.assertFalse(validation.write_authorized)
        self.assertFalse(binding.approval_bound)
        self.assertFalse(binding.human_approved)
        self.assertFalse(binding.apply_authorized)
        self.assertFalse(binding.production_write_authorized)

    def test_shutdown_text_is_rejected_even_with_recomputed_digest(self):
        render = self._render()
        payload = render.payload_xml.replace("<shutdown />", "<shutdown>true</shutdown>")
        tampered = replace(
            render,
            payload_xml=payload,
            payload_digest_sha256=hashlib.sha256(payload.encode("utf-8")).hexdigest(),
        )
        with self.assertRaisesRegex(CiscoValidationApprovalError, "empty YANG leaf"):
            validate_desired_state_render(
                target_id="sw-core-01",
                pre_state_sha256=PRE_STATE,
                render=tampered,
            )

    def test_shutdown_nested_xml_is_rejected_even_with_recomputed_digest(self):
        render = self._render()
        payload = render.payload_xml.replace("<shutdown />", "<shutdown><x /></shutdown>")
        tampered = replace(
            render,
            payload_xml=payload,
            payload_digest_sha256=hashlib.sha256(payload.encode("utf-8")).hexdigest(),
        )
        with self.assertRaisesRegex(CiscoValidationApprovalError, "nested XML"):
            validate_desired_state_render(
                target_id="sw-core-01",
                pre_state_sha256=PRE_STATE,
                render=tampered,
            )

    def test_wrong_leaf_for_shutdown_feature_is_rejected(self):
        render = self._render()
        payload = render.payload_xml.replace("<shutdown />", "<mtu>1500</mtu>")
        tampered = replace(
            render,
            payload_xml=payload,
            payload_digest_sha256=hashlib.sha256(payload.encode("utf-8")).hexdigest(),
        )
        with self.assertRaisesRegex(CiscoValidationApprovalError, "shutdown slice"):
            validate_desired_state_render(
                target_id="sw-core-01",
                pre_state_sha256=PRE_STATE,
                render=tampered,
            )

    def test_router_26_uses_same_empty_leaf_validation(self):
        render = self._render(model="C8000V", iosxe_version="26.1.1")
        validation = validate_desired_state_render(
            target_id="edge-lab-01",
            pre_state_sha256=PRE_STATE,
            render=render,
        )
        self.assertEqual(validation.documentation_train, "26")
        self.assertEqual(validation.platform_family, "Catalyst 8000V")
        self.assertEqual(validation.role, "router")


if __name__ == "__main__":
    unittest.main()
