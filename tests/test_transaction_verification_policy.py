import pytest

from router_configuration.transaction_verification_policy import (
    VerificationCheck,
    derive_transaction_verification_policy,
)


def test_multiwan_vpn_dns_policy_is_effect_scoped_and_management_safe():
    policy = derive_transaction_verification_policy(["multiwan", "wireguard", "dns"])
    assert set(policy.required_checks) == {
        VerificationCheck.MANAGEMENT,
        VerificationCheck.INTENDED_STATE,
        VerificationCheck.WAN,
        VerificationCheck.ROUTING,
        VerificationCheck.VPN,
        VerificationCheck.DNS,
    }
    payload = policy.as_dict()
    assert payload["management_required"] is True
    assert payload["transport_present"] is False
    assert payload["production_writer_available"] is False
    assert payload["write_authorized"] is False


def test_verification_policy_fails_closed_for_unknown_feature():
    with pytest.raises(ValueError, match="no accepted mapping"):
        derive_transaction_verification_policy(["future-feature"])
