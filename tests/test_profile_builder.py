import unittest

from router_configuration.deployment_profile import DeploymentProfileValidator
from router_configuration.profile_builder import (
    GuidedProfileBuilder,
    GuidedProfileRequest,
    prompt_guided_request,
)


class GuidedProfileBuilderTests(unittest.TestCase):
    def test_safe_defaults_produce_read_only_10g_1g_profile(self):
        profile = GuidedProfileBuilder().build(
            GuidedProfileRequest(
                site_name="rd",
                device_id="rd-router-01",
                management_target="192.168.11.1",
                recovery_method="local-console",
            )
        )
        self.assertFalse(profile["allow_write"])
        self.assertFalse(profile["intent"]["security"]["management_from_wan"])
        validation = DeploymentProfileValidator().validate(profile)
        self.assertTrue(validation.ok, validation.errors)
        self.assertEqual(dict(validation.wan_weights), {"wan-primary": 10, "wan-secondary": 1})

    def test_wireguard_requires_secret_reference(self):
        with self.assertRaisesRegex(ValueError, "secret reference"):
            GuidedProfileBuilder().build(
                GuidedProfileRequest(
                    site_name="rd",
                    device_id="r1",
                    management_target="192.168.11.1",
                    enable_wireguard=True,
                )
            )

    def test_duplicate_physical_port_is_rejected_by_generated_profile_validation(self):
        with self.assertRaisesRegex(ValueError, "duplicate interface assignment|core interface"):
            GuidedProfileBuilder().build(
                GuidedProfileRequest(
                    site_name="rd",
                    device_id="r1",
                    management_target="192.168.11.1",
                    wan_primary_interface="ether1",
                    wan_secondary_interface="ether1",
                )
            )

    def test_prompt_collects_only_basic_network_facts(self):
        answers = iter([
            "rd",
            "rd-router-01",
            "192.168.11.1",
            "",
            "",
            "",
            "",
            "local-console",
            "y",
            "vault://routers/rd-router-01/wireguard",
            "y",
        ])
        request = prompt_guided_request(input_fn=lambda _prompt: next(answers))
        self.assertEqual(request.model, "CCR2116-12G-4S+")
        self.assertEqual(request.wan_primary_interface, "sfp-sfpplus1")
        self.assertEqual(request.wan_secondary_interface, "ether1")
        self.assertEqual(request.core_interface, "sfp-sfpplus2")
        self.assertTrue(request.enable_wireguard)
        self.assertTrue(request.enable_qos)
        self.assertTrue(request.wireguard_secret_ref.startswith("vault://"))


if __name__ == "__main__":
    unittest.main()
