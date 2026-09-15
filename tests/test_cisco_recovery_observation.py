import unittest

from router_configuration.vendors.cisco.recovery_observation import (
    CiscoRecoveryObservationError,
    validate_recovery_observation_candidate,
)
from router_configuration.vendors.cisco.transaction_execution_contract import build_recovery_execution_contract
from router_configuration.vendors.cisco.transaction_recovery import build_cisco_backup_evidence, build_cisco_recovery_plan
from router_configuration.vendors.cisco.validation_approval import CiscoApprovalBinding

CANDIDATE = "urn:ietf:params:netconf:capability:candidate:1.0"
CONFIRMED = "urn:ietf:params:netconf:capability:confirmed-commit:1.1"


def contract():
    approval = CiscoApprovalBinding(
        change_id="CHG-C10-OBS-001",
        target_id="c8kv-lab-01",
        pre_state_sha256="a" * 64,
        payload_digest_sha256="b" * 64,
        schema_inventory_digest_sha256="c" * 64,
        catalog_digest_sha256="d" * 64,
        validation_sha256="e" * 64,
        model="C8000V",
        iosxe_version="17.18.1a",
        documentation_train="17.18",
        platform_family="Catalyst 8000V",
        role="router",
        feature_id="interface.description.set",
        target_datastore="candidate",
        approval_sha256="f" * 64,
    )
    backup = build_cisco_backup_evidence(
        target_id=approval.target_id,
        model=approval.model,
        iosxe_version=approval.iosxe_version,
        pre_state_sha256=approval.pre_state_sha256,
        snapshot_ref="artifact:cisco:c10:observation-prechange",
        snapshot_sha256="1" * 64,
    )
    plan = build_cisco_recovery_plan(
        approval=approval,
        backup=backup,
        c09_bundle_sha256="2" * 64,
        management_baseline_sha256="3" * 64,
        connectivity_baseline_sha256="4" * 64,
        observed_netconf_capabilities={CANDIDATE, CONFIRMED},
    )
    return build_recovery_execution_contract(plan)


def candidate(item=None, **overrides):
    c = item or contract()
    payload = {
        "schema_version": "cisco-c10-live-recovery-observation/1",
        "target_id": c.target_id,
        "model": c.model,
        "iosxe_version": c.iosxe_version,
        "source_sha": "1" * 40,
        "source_run_id": "run-34999999999",
        "recovery_plan_sha256": c.recovery_plan_sha256,
        "execution_contract_sha256": c.contract_sha256,
        "outcome": "automatic_rollback",
        "observed_phase_order": list(c.phase_order),
        "live_execution_observed": True,
        "live_rollback_observed": True,
        "restored_state_verified": True,
        "repository_live_evidence_accepted": False,
        "c10_complete": False,
        "physical_device_verified": False,
        "production_writer_available": False,
        "production_write_authorized": False,
    }
    payload.update(overrides)
    return payload


class CiscoRecoveryObservationTests(unittest.TestCase):
    def test_candidate_is_deterministic_but_never_repository_accepted(self):
        c = contract()
        first = validate_recovery_observation_candidate(candidate(c), contract=c)
        second = validate_recovery_observation_candidate(candidate(c), contract=c)
        self.assertEqual(first, second)
        self.assertTrue(first.candidate_claims_live_execution)
        self.assertTrue(first.candidate_claims_live_rollback)
        self.assertTrue(first.candidate_claims_restored_state_verified)
        self.assertFalse(first.repository_live_evidence_accepted)
        self.assertFalse(first.c10_complete)
        self.assertFalse(first.physical_device_verified)
        self.assertFalse(first.production_writer_available)
        self.assertFalse(first.production_write_authorized)
        self.assertEqual(len(first.observation_sha256), 64)

    def test_confirmed_path_is_allowed_without_rollback_claim(self):
        c = contract()
        result = validate_recovery_observation_candidate(
            candidate(c, outcome="confirmed", live_rollback_observed=False, restored_state_verified=False),
            contract=c,
        )
        self.assertEqual(result.outcome, "confirmed")
        self.assertFalse(result.candidate_claims_live_rollback)

    def test_contract_and_plan_digests_must_match(self):
        c = contract()
        with self.assertRaisesRegex(CiscoRecoveryObservationError, "plan digest mismatch"):
            validate_recovery_observation_candidate(candidate(c, recovery_plan_sha256="9" * 64), contract=c)
        with self.assertRaisesRegex(CiscoRecoveryObservationError, "contract digest mismatch"):
            validate_recovery_observation_candidate(candidate(c, execution_contract_sha256="8" * 64), contract=c)

    def test_identity_must_match_contract(self):
        c = contract()
        with self.assertRaisesRegex(CiscoRecoveryObservationError, "target differs"):
            validate_recovery_observation_candidate(candidate(c, target_id="other"), contract=c)
        with self.assertRaisesRegex(CiscoRecoveryObservationError, "platform/version differs"):
            validate_recovery_observation_candidate(candidate(c, iosxe_version="26.1.1"), contract=c)

    def test_phase_order_is_exact(self):
        c = contract()
        phases = list(c.phase_order)
        phases[0], phases[1] = phases[1], phases[0]
        with self.assertRaisesRegex(CiscoRecoveryObservationError, "phase order differs"):
            validate_recovery_observation_candidate(candidate(c, observed_phase_order=phases), contract=c)

    def test_automatic_rollback_requires_rollback_and_restore_evidence(self):
        c = contract()
        for field in ("live_rollback_observed", "restored_state_verified"):
            with self.subTest(field=field):
                with self.assertRaisesRegex(CiscoRecoveryObservationError, "requires observed rollback"):
                    validate_recovery_observation_candidate(candidate(c, **{field: False}), contract=c)

    def test_candidate_cannot_self_promote(self):
        c = contract()
        for field in (
            "repository_live_evidence_accepted",
            "c10_complete",
            "physical_device_verified",
            "production_writer_available",
            "production_write_authorized",
        ):
            with self.subTest(field=field):
                with self.assertRaisesRegex(CiscoRecoveryObservationError, "cannot self-promote"):
                    validate_recovery_observation_candidate(candidate(c, **{field: True}), contract=c)

    def test_live_execution_flag_and_source_provenance_are_required(self):
        c = contract()
        with self.assertRaisesRegex(CiscoRecoveryObservationError, "live_execution_observed"):
            validate_recovery_observation_candidate(candidate(c, live_execution_observed=False), contract=c)
        with self.assertRaisesRegex(CiscoRecoveryObservationError, "Git SHA"):
            validate_recovery_observation_candidate(candidate(c, source_sha="bad"), contract=c)
        with self.assertRaisesRegex(CiscoRecoveryObservationError, "source_run_id"):
            validate_recovery_observation_candidate(candidate(c, source_run_id="bad value"), contract=c)


if __name__ == "__main__":
    unittest.main()
