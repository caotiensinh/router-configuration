import hashlib
import unittest
from dataclasses import replace

from router_configuration.vendors.cisco.desired_state import render_interface_mtu
from router_configuration.vendors.cisco.validation_approval import (
    CiscoValidationApprovalError,
    build_approval_binding,
    validate_desired_state_render,
)

MODULES = {"Cisco-IOS-XE-native"}
CAPABILITIES = {"urn:ietf:params:netconf:capability:candidate:1.0"}
SCHEMA_DIGEST = "b" * 64
PRE_STATE = "a" * 64


def render_mtu(mtu=1500):
    return render_interface_mtu(
        model="C9300-24T",
        iosxe_version="17.18.1a",
        schema_inventory_digest_sha256=SCHEMA_DIGEST,
        observed_modules=MODULES,
        netconf_capabilities=CAPABILITIES,
        interface_name="1/0/1",
        mtu=mtu,
    )


class CiscoValidationMtuTests(unittest.TestCase):
    def test_mtu_render_validates_and_binds_without_authority(self):
        render = render_mtu(9216)
        validation = validate_desired_state_render(
            target_id="sw-core-01",
            pre_state_sha256=PRE_STATE,
            render=render,
        )
        binding = build_approval_binding(
            change_id="CHG-C08-MTU-001",
            target_id="sw-core-01",
            pre_state_sha256=PRE_STATE,
            render=render,
            validation=validation,
        )
        self.assertTrue(validation.passed)
        self.assertEqual(validation.feature_id, "interface.mtu.set")
        self.assertEqual(binding.feature_id, "interface.mtu.set")
        self.assertFalse(validation.c08_complete)
        self.assertFalse(binding.apply_authorized)
        self.assertFalse(binding.production_write_authorized)

    def test_mtu_wrong_leaf_is_rejected_even_with_matching_digest(self):
        render = render_mtu(1500)
        payload = render.payload_xml.replace("<mtu>1500</mtu>", "<description>1500</description>")
        tampered = replace(
            render,
            payload_xml=payload,
            payload_digest_sha256=hashlib.sha256(payload.encode("utf-8")).hexdigest(),
        )
        with self.assertRaisesRegex(CiscoValidationApprovalError, "structure differs"):
            validate_desired_state_render(
                target_id="sw-core-01",
                pre_state_sha256=PRE_STATE,
                render=tampered,
            )

    def test_mtu_outside_source_range_is_rejected_after_tamper(self):
        render = render_mtu(1500)
        payload = render.payload_xml.replace("<mtu>1500</mtu>", "<mtu>18001</mtu>")
        tampered = replace(
            render,
            payload_xml=payload,
            payload_digest_sha256=hashlib.sha256(payload.encode("utf-8")).hexdigest(),
        )
        with self.assertRaisesRegex(CiscoValidationApprovalError, "source-bound range"):
            validate_desired_state_render(
                target_id="sw-core-01",
                pre_state_sha256=PRE_STATE,
                render=tampered,
            )

    def test_unknown_feature_fails_closed(self):
        render = replace(render_mtu(), feature_id="interface.unknown.set")
        with self.assertRaisesRegex(CiscoValidationApprovalError, "unsupported desired-state feature"):
            validate_desired_state_render(
                target_id="sw-core-01",
                pre_state_sha256=PRE_STATE,
                render=render,
            )


if __name__ == "__main__":
    unittest.main()
