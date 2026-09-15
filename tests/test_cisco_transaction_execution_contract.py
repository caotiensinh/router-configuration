import unittest
from dataclasses import replace

from tests.test_cisco_transaction_recovery import plan
from router_configuration.vendors.cisco.transaction_execution_contract import (
    CiscoRecoveryExecutionContractError,
    build_recovery_execution_contract,
    contract_only_status,
    validate_recovery_plan_for_executor,
)


class CiscoTransactionExecutionContractTests(unittest.TestCase):
    def test_contract_is_deterministic_and_transport_free(self):
        first = build_recovery_execution_contract(plan())
        second = build_recovery_execution_contract(plan())
        self.assertEqual(first, second)
        self.assertEqual(first.transport, "netconf")
        self.assertEqual(first.confirmed_commit_timeout_seconds, 600)
        self.assertEqual(len(first.phase_order), 13)
        self.assertTrue(first.candidate_datastore_required)
        self.assertTrue(first.confirmation_requires_all_verifications)
        self.assertTrue(first.automatic_rollback_on_unconfirmed_change)
        self.assertFalse(first.executor_implementation_present)
        self.assertFalse(first.live_execution_observed)
        self.assertFalse(first.live_rollback_observed)
        self.assertFalse(first.restored_state_verified)
        self.assertFalse(first.c10_complete)
        self.assertFalse(first.production_writer_available)
        self.assertFalse(first.production_write_authorized)
        self.assertEqual(len(first.contract_sha256), 64)

    def test_execution_contract_binds_exact_recovery_inputs(self):
        recovery = plan()
        contract = build_recovery_execution_contract(recovery)
        self.assertEqual(contract.recovery_plan_sha256, recovery.plan_sha256)
        self.assertEqual(contract.approval_sha256, recovery.approval_sha256)
        self.assertEqual(contract.c09_bundle_sha256, recovery.c09_bundle_sha256)
        self.assertEqual(contract.backup_evidence_sha256, recovery.backup_evidence_sha256)
        self.assertEqual(contract.confirmed_commit_capability, recovery.confirmed_commit_capability)

    def test_plan_digest_tampering_is_rejected(self):
        tampered = replace(plan(), plan_sha256="9" * 64)
        with self.assertRaisesRegex(CiscoRecoveryExecutionContractError, "digest mismatch"):
            validate_recovery_plan_for_executor(tampered)

    def test_phase_order_is_immutable(self):
        recovery = plan()
        altered = replace(recovery, required_runtime_order=tuple(reversed(recovery.required_runtime_order)))
        with self.assertRaisesRegex(CiscoRecoveryExecutionContractError, "digest mismatch"):
            validate_recovery_plan_for_executor(altered)

    def test_transport_and_capability_guards_fail_closed(self):
        recovery = plan()
        with self.assertRaises(CiscoRecoveryExecutionContractError):
            validate_recovery_plan_for_executor(replace(recovery, transport="restconf"))
        with self.assertRaises(CiscoRecoveryExecutionContractError):
            validate_recovery_plan_for_executor(replace(recovery, candidate_capability="wrong"))
        with self.assertRaises(CiscoRecoveryExecutionContractError):
            validate_recovery_plan_for_executor(replace(recovery, confirmed_commit_capability="wrong"))

    def test_timeout_and_recovery_guards_fail_closed(self):
        recovery = plan()
        for changed in (
            replace(recovery, confirmed_commit_timeout_seconds=30),
            replace(recovery, restconf_confirmed_commit_allowed=True),
            replace(recovery, automatic_rollback_required=False),
            replace(recovery, final_confirmation_requires_all_verifications=False),
        ):
            with self.subTest(changed=changed):
                with self.assertRaises(CiscoRecoveryExecutionContractError):
                    validate_recovery_plan_for_executor(changed)

    def test_pre_executor_cannot_claim_completion_or_write_availability(self):
        recovery = plan()
        for changed in (
            replace(recovery, c10_complete=True),
            replace(recovery, apply_available=True),
            replace(recovery, production_writer_available=True),
            replace(recovery, production_write_authorized=True),
        ):
            with self.subTest(changed=changed):
                with self.assertRaises(CiscoRecoveryExecutionContractError):
                    validate_recovery_plan_for_executor(changed)

    def test_contract_only_status_cannot_close_c10(self):
        status = contract_only_status()
        self.assertEqual(status["phase_count"], 13)
        self.assertEqual(status["confirmed_commit_timeout_seconds"], 600)
        self.assertFalse(status["executor_implementation_present"])
        self.assertFalse(status["synthetic_fixture_can_complete_c10"])
        self.assertFalse(status["live_execution_observed"])
        self.assertFalse(status["live_rollback_observed"])
        self.assertFalse(status["restored_state_verified"])
        self.assertFalse(status["c10_complete"])
        self.assertFalse(status["production_writer_available"])
        self.assertFalse(status["production_write_authorized"])
        self.assertEqual(len(status["status_sha256"]), 64)


if __name__ == "__main__":
    unittest.main()
