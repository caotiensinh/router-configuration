import unittest

from router_configuration.transaction_failure_scenarios import (
    FailureScenario,
    assess_failure_scenario,
)


class TransactionFailureScenarioTests(unittest.TestCase):
    def test_internet_down_link_up_requires_management_to_survive(self):
        result = assess_failure_scenario(
            FailureScenario.INTERNET_DOWN_LINK_UP,
            {
                "link_running": True,
                "internet_reachable": False,
                "management_reachable": True,
            },
        )
        self.assertTrue(result.observed)
        self.assertTrue(result.rollback_required)
        self.assertIn("internet_recovered", result.required_recovery_checks)
        self.assertFalse(result.as_dict()["write_authorized"])

    def test_dns_failure_is_distinguished_from_general_internet_loss(self):
        result = assess_failure_scenario(
            FailureScenario.DNS_FAILURE,
            {
                "public_ip_reachable": True,
                "dns_resolution_ok": False,
                "management_reachable": True,
            },
        )
        self.assertTrue(result.observed)
        self.assertIn("dns_recovered", result.required_recovery_checks)

    def test_route_loss_requires_boolean_evidence_and_fails_closed(self):
        with self.assertRaisesRegex(ValueError, "boolean observation"):
            assess_failure_scenario(
                FailureScenario.DEFAULT_ROUTE_LOSS,
                {"default_route_usable": None, "management_reachable": True},
            )


if __name__ == "__main__":
    unittest.main()
