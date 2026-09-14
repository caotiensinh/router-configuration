import unittest

from router_configuration.transaction_verification_policy import (
    VerificationCheck,
    derive_transaction_verification_policy,
)


class TransactionVerificationPolicyTests(unittest.TestCase):
    def test_multiwan_vpn_dns_policy_is_effect_scoped_and_management_safe(self):
        policy = derive_transaction_verification_policy(["multiwan", "wireguard", "dns"])
        self.assertEqual(
            set(policy.required_checks),
            {
                VerificationCheck.MANAGEMENT,
                VerificationCheck.INTENDED_STATE,
                VerificationCheck.WAN,
                VerificationCheck.ROUTING,
                VerificationCheck.VPN,
                VerificationCheck.DNS,
            },
        )
        payload = policy.as_dict()
        self.assertTrue(payload["management_required"])
        self.assertFalse(payload["transport_present"])
        self.assertFalse(payload["production_writer_available"])
        self.assertFalse(payload["write_authorized"])

    def test_verification_policy_fails_closed_for_unknown_feature(self):
        with self.assertRaisesRegex(ValueError, "no accepted mapping"):
            derive_transaction_verification_policy(["future-feature"])


if __name__ == "__main__":
    unittest.main()
