import unittest
from dataclasses import replace

from router_configuration.vendors.cisco.transaction_recovery import (
    CiscoTransactionRecoveryError,
    build_cisco_backup_evidence,
    build_cisco_recovery_plan,
    contract_only_status,
    validate_cisco_backup_evidence,
)
from router_configuration.vendors.cisco.validation_approval import CiscoApprovalBinding


CANDIDATE = "urn:ietf:params:netconf:capability:candidate:1.0"
CONFIRMED_10 = "urn:ietf:params:netconf:capability:confirmed-commit:1.0"
CONFIRMED_11 = "urn:ietf:params:netconf:capability:confirmed-commit:1.1"
PRE_STATE = "a" * 64
PAYLOAD_DIGEST = "b" * 64
SCHEMA_DIGEST = "c" * 64
CATALOG_DIGEST = "d" * 64
VALIDATION_DIGEST = "e" * 64
APPROVAL_DIGEST = "f" * 64


def approval(**overrides) -> CiscoApprovalBinding:
    params = {
        "change_id": "CHG-C10-001",
        "target_id": "c8kv-lab-01",
        "pre_state_sha256": PRE_STATE,
        "payload_digest_sha256": PAYLOAD_DIGEST,
        "schema_inventory_digest_sha256": SCHEMA_DIGEST,
        "catalog_digest_sha256": CATALOG_DIGEST,
        "validation_sha256": VALIDATION_DIGEST,
        "model": "C8000V",
        "iosxe_version": "17.18.1a",
        "documentation_train": "17.18",
        "platform_family": "Catalyst 8000V",
        "role": "router",
        "feature_id": "interface.description.set",
        "target_datastore": "candidate",
        "approval_sha256": APPROVAL_DIGEST,
    }
    params.update(overrides)
    return CiscoApprovalBinding(**params)


def backup(**overrides):
    params = {
        "target_id": "c8kv-lab-01",
        "model": "C8000V",
        "iosxe_version": "17.18.1a",
        "pre_state_sha256": PRE_STATE,
        "snapshot_ref": "artifact:cisco:c10:prechange",
        "snapshot_sha256": "1" * 64,
    }
    params.update(overrides)
    return build_cisco_backup_evidence(**params)


def plan(**overrides):
    params = {
        "approval": approval(),
        "backup": backup(),
        "c09_bundle_sha256": "2" * 64,
        "management_baseline_sha256": "3" * 64,
        "connectivity_baseline_sha256": "4" * 64,
        "observed_netconf_capabilities": {CANDIDATE, CONFIRMED_11},
    }
    params.update(overrides)
    return build_cisco_recovery_plan(**params)


class CiscoTransactionRecoveryTests(unittest.TestCase):
    def test_contract_only_status_cannot_close_c10(self) -> None:
        status = contract_only_status()
        self.assertEqual(status["documented_default_confirm_timeout_seconds"], 600)
        self.assertFalse(status["restconf_confirmed_commit_allowed"])
        self.assertFalse(status["synthetic_fixture_can_complete_c10"])
        self.assertFalse(status["live_rollback_observed"])
        self.assertFalse(status["restored_state_verified"])
        self.assertFalse(status["c10_complete"])
        self.assertFalse(status["apply_available"])
        self.assertFalse(status["production_writer_available"])
        self.assertFalse(status["production_write_authorized"])

    def test_backup_evidence_is_repository_safe_and_deterministic(self) -> None:
        first = backup()
        second = backup()
        self.assertEqual(first, second)
        validate_cisco_backup_evidence(first)
        self.assertTrue(first.readable)
        self.assertTrue(first.repository_safe)
        self.assertFalse(first.secret_values_present)
        self.assertFalse(first.binary_payload_present)
        self.assertFalse(first.production_writer_available)
        self.assertFalse(first.production_write_authorized)
        self.assertEqual(len(first.evidence_sha256), 64)

    def test_backup_rejects_unsafe_reference_or_digest(self) -> None:
        with self.assertRaisesRegex(CiscoTransactionRecoveryError, "opaque non-secret"):
            backup(snapshot_ref="https://host/backup?token=secret")
        with self.assertRaisesRegex(CiscoTransactionRecoveryError, "SHA-256"):
            backup(snapshot_sha256="bad")

    def test_tampered_backup_evidence_is_rejected(self) -> None:
        item = replace(backup(), snapshot_sha256="9" * 64)
        with self.assertRaisesRegex(CiscoTransactionRecoveryError, "digest mismatch"):
            validate_cisco_backup_evidence(item)

    def test_recovery_plan_is_deterministic_and_pre_executor(self) -> None:
        first = plan()
        second = plan(observed_netconf_capabilities=[CONFIRMED_11, CANDIDATE])
        self.assertEqual(first, second)
        self.assertEqual(first.transport, "netconf")
        self.assertEqual(first.confirmed_commit_timeout_seconds, 600)
        self.assertFalse(first.restconf_confirmed_commit_allowed)
        self.assertTrue(first.automatic_rollback_required)
        self.assertTrue(first.final_confirmation_requires_all_verifications)
        self.assertFalse(first.c10_complete)
        self.assertFalse(first.apply_available)
        self.assertFalse(first.production_writer_available)
        self.assertFalse(first.production_write_authorized)
        self.assertEqual(len(first.plan_sha256), 64)

    def test_plan_contains_source_bound_recovery_order(self) -> None:
        order = plan().required_runtime_order
        self.assertLess(order.index("lock_running_datastore"), order.index("lock_candidate_datastore"))
        self.assertLess(order.index("lock_candidate_datastore"), order.index("apply_exact_approved_candidate"))
        self.assertLess(
            order.index("apply_exact_approved_candidate"),
            order.index("issue_confirmed_commit_using_documented_default_timeout"),
        )
        self.assertLess(
            order.index("verify_intended_state"),
            order.index("confirm_commit_permanently_only_if_all_verifications_pass"),
        )
        self.assertIn("otherwise_withhold_confirmation_and_allow_automatic_rollback", order)
        self.assertIn("verify_recovered_management_connectivity_and_prechange_state", order)

    def test_candidate_and_confirmed_commit_capabilities_are_mandatory(self) -> None:
        with self.assertRaisesRegex(CiscoTransactionRecoveryError, "candidate capability"):
            plan(observed_netconf_capabilities={CONFIRMED_11})
        with self.assertRaisesRegex(CiscoTransactionRecoveryError, "confirmed-commit capability"):
            plan(observed_netconf_capabilities={CANDIDATE})

    def test_confirmed_commit_version_is_observed_not_guessed(self) -> None:
        self.assertEqual(plan(observed_netconf_capabilities={CANDIDATE, CONFIRMED_10}).confirmed_commit_capability, CONFIRMED_10)
        self.assertEqual(plan(observed_netconf_capabilities={CANDIDATE, CONFIRMED_11}).confirmed_commit_capability, CONFIRMED_11)
        with self.assertRaisesRegex(CiscoTransactionRecoveryError, "ambiguous"):
            plan(observed_netconf_capabilities={CANDIDATE, CONFIRMED_10, CONFIRMED_11})

    def test_backup_must_bind_exact_target_platform_and_pre_state(self) -> None:
        cases = (
            (backup(target_id="c8kv-lab-02"), "target differs"),
            (backup(model="C8000V-OTHER"), "platform/version differs"),
            (backup(iosxe_version="26.1.1"), "platform/version differs"),
            (backup(pre_state_sha256="9" * 64), "pre-state differs"),
        )
        for item, message in cases:
            with self.subTest(message=message):
                with self.assertRaisesRegex(CiscoTransactionRecoveryError, message):
                    plan(backup=item)

    def test_all_external_baseline_and_c09_hashes_are_required(self) -> None:
        for field in (
            "c09_bundle_sha256",
            "management_baseline_sha256",
            "connectivity_baseline_sha256",
        ):
            with self.subTest(field=field):
                with self.assertRaisesRegex(CiscoTransactionRecoveryError, "SHA-256"):
                    plan(**{field: "bad"})

    def test_c08_binding_cannot_carry_write_or_human_approval_state(self) -> None:
        for field in (
            "apply_authorized",
            "write_authorized",
            "production_write_authorized",
            "human_approved",
        ):
            with self.subTest(field=field):
                item = approval(**{field: True})
                with self.assertRaisesRegex(CiscoTransactionRecoveryError, "pre-write fingerprint"):
                    plan(approval=item)

    def test_candidate_datastore_is_required(self) -> None:
        with self.assertRaisesRegex(CiscoTransactionRecoveryError, "candidate datastore"):
            plan(approval=approval(target_datastore="running"))

    def test_iosxe_26_binding_uses_same_confirmed_commit_contract(self) -> None:
        appr = approval(
            model="C8000V",
            iosxe_version="26.1.1",
            documentation_train="26",
        )
        bkp = backup(iosxe_version="26.1.1")
        result = plan(approval=appr, backup=bkp)
        self.assertEqual(result.iosxe_version, "26.1.1")
        self.assertEqual(result.confirmed_commit_timeout_seconds, 600)
        self.assertFalse(result.restconf_confirmed_commit_allowed)


if __name__ == "__main__":
    unittest.main()
