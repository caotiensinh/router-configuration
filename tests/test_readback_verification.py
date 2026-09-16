import unittest

from router_configuration.readback_verification import (
    ReadBackVerificationError,
    build_readback_verification,
)


def evidence(**overrides):
    base = {
        "evidence_ref": "runtime-evidence/omada/fresh-readback",
        "fresh_read": True,
        "independently_acquired": True,
        "apply_observation_reused": False,
    }
    base.update(overrides)
    return base


class ReadBackVerificationTests(unittest.TestCase):
    def test_exact_fresh_readback_passes_without_execution_capability(self) -> None:
        desired = {"network": {"vlan": 20, "enabled": True}}
        result = build_readback_verification(
            source_plan_id="plan-20",
            desired_managed_state=desired,
            readback_managed_state={"network": {"vlan": 20, "enabled": True}},
            evidence=evidence(),
        ).as_dict()
        self.assertEqual(result["acceptance"], "PASS")
        self.assertEqual(result["verification_state"], "VERIFIED")
        self.assertEqual(result["drift_count"], 0)
        self.assertIs(result["readback_matches_desired"], True)
        self.assertIs(result["transport_present"], False)
        self.assertIs(result["apply_available"], False)
        self.assertIs(result["write_authorized"], False)

    def test_readback_mismatch_returns_deterministic_drift_evidence(self) -> None:
        result = build_readback_verification(
            source_plan_id="plan-21",
            desired_managed_state={"network": {"vlan": 20}},
            readback_managed_state={"network": {"vlan": 30, "unexpected": True}},
            evidence=evidence(),
        ).as_dict()
        self.assertEqual(result["acceptance"], "FAIL")
        self.assertEqual(result["verification_state"], "MISMATCH")
        self.assertEqual(result["drift_count"], 2)
        self.assertEqual([item["path"] for item in result["drift"]], ["network.unexpected", "network.vlan"])

    def test_stale_reused_or_secret_bearing_evidence_fails_closed(self) -> None:
        desired = {"x": 1}
        with self.assertRaisesRegex(ReadBackVerificationError, "fresh_read=true"):
            build_readback_verification(
                source_plan_id="plan-a", desired_managed_state=desired, readback_managed_state=desired, evidence=evidence(fresh_read=False)
            )
        with self.assertRaisesRegex(ReadBackVerificationError, "apply_observation_reused=false"):
            build_readback_verification(
                source_plan_id="plan-b", desired_managed_state=desired, readback_managed_state=desired, evidence=evidence(apply_observation_reused=True)
            )
        with self.assertRaisesRegex(ReadBackVerificationError, "secret fields"):
            build_readback_verification(
                source_plan_id="plan-c", desired_managed_state=desired, readback_managed_state=desired, evidence=evidence(token="should-not-exist")
            )


if __name__ == "__main__":
    unittest.main()
