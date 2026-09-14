import pytest

from router_configuration.transaction_failure_scenarios import (
    FailureScenario,
    assess_failure_scenario,
)


def test_internet_down_link_up_requires_management_to_survive():
    result = assess_failure_scenario(
        FailureScenario.INTERNET_DOWN_LINK_UP,
        {
            "link_running": True,
            "internet_reachable": False,
            "management_reachable": True,
        },
    )
    assert result.observed is True
    assert result.rollback_required is True
    assert "internet_recovered" in result.required_recovery_checks
    assert result.as_dict()["write_authorized"] is False


def test_dns_failure_is_distinguished_from_general_internet_loss():
    result = assess_failure_scenario(
        FailureScenario.DNS_FAILURE,
        {
            "public_ip_reachable": True,
            "dns_resolution_ok": False,
            "management_reachable": True,
        },
    )
    assert result.observed is True
    assert "dns_recovered" in result.required_recovery_checks


def test_route_loss_requires_boolean_evidence_and_fails_closed():
    with pytest.raises(ValueError, match="boolean observation"):
        assess_failure_scenario(
            FailureScenario.DEFAULT_ROUTE_LOSS,
            {"default_route_usable": None, "management_reachable": True},
        )
