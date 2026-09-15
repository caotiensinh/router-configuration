import hashlib
import json
import unittest

from router_configuration.production_transaction_readiness import (
    ProductionTransactionReadinessError,
    build_production_transaction_readiness,
    evaluate_production_verification_outcome,
)
from router_configuration.transaction_backup_evidence import (
    build_transaction_backup_evidence,
)
from router_configuration.transaction_envelope import build_transaction_envelope
from router_configuration.transaction_lifecycle import (
    initialize_transaction_lifecycle,
    transition_transaction_lifecycle,
)


def _sha(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def _canonical_sha256(value):
    return hashlib.sha256(
        json.dumps(
            value,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=False,
            default=str,
        ).encode("utf-8")
    ).hexdigest()


class ProductionTransactionReadinessTests(unittest.TestCase):
    def _render_plan(self):
        plan = {
            "schema_version": "routeros-render-plan/1",
            "device_id": "rd-router-01",
            "source_ir_sha256": _sha("ir"),
            "claim": "generation_complete",
            "complete": True,
            "command_format": "routeros-script/1",
            "commands": [],
            "blocked_operations": [],
            "secret_references": [],
            "vendor_commands_present": False,
            "secrets_resolved": False,
            "transport_present": False,
            "apply_available": False,
            "write_authorized": False,
        }
        plan["render_sha256"] = _canonical_sha256(plan)
        return plan

    def _fixture(self, *, wireguard=True):
        pre_state = _sha("pre-state")
        render_plan = self._render_plan()
        sanitized = build_transaction_backup_evidence(
            kind="sanitized_export",
            artifact_ref="artifact://prechange/sanitized-export.rsc",
            sha256=_sha("sanitized-export"),
            pre_state_sha256=pre_state,
        ).as_dict()
        protected = build_transaction_backup_evidence(
            kind="protected_ephemeral_binary",
            artifact_ref="protected-ref://router-backup/prechange-001",
            sha256=_sha("binary-backup"),
            pre_state_sha256=pre_state,
        ).as_dict()
        envelope = build_transaction_envelope(
            render_plan=render_plan,
            pre_state_sha256=pre_state,
            backup=sanitized,
            approval={
                "approved": True,
                "plan_sha256": render_plan["render_sha256"],
                "approver_ref": "operator://change-approval/001",
            },
            management_path={
                "ok": True,
                "evidence_ref": "evidence://management/prechange",
            },
            connectivity_baseline={
                "ok": True,
                "evidence_ref": "evidence://connectivity/prechange",
            },
        ).as_dict()
        lifecycle = initialize_transaction_lifecycle(envelope=envelope).as_dict()
        lifecycle = transition_transaction_lifecycle(
            lifecycle=lifecycle,
            to_phase="authorized",
            evidence={
                "evidence_ref": "evidence://approval/authorized",
                "authorized": True,
                "exact_envelope_revalidated": True,
                "transaction_id": envelope["transaction_id"],
            },
        ).as_dict()
        profile = {
            "intent": {
                "vpn": {
                    "wireguard": {
                        "enabled": wireguard,
                    }
                }
            }
        }
        management = {
            "schema_version": "routeros-production-management-readiness/1",
            "pre_change_reachable": True,
            "independent_probe": True,
            "monitor_during_apply": True,
            "post_apply_verification_required": True,
            "rollback_recovery_verification_required": True,
            "evidence_ref": "evidence://management/production-readiness",
        }
        names = ["management", "wan", "dns", "routing"]
        if wireguard:
            names.append("vpn")
        verification = {
            "schema_version": "routeros-production-verification-contract/1",
            "stop_on_failure": True,
            "checks": {
                name: {
                    "required": True,
                    "readback_required": True,
                    "behavior_verification_required": True,
                    "evidence_ref": f"evidence://verification-contract/{name}",
                }
                for name in names
            },
        }
        rollback = {
            "schema_version": "routeros-production-rollback-contract/1",
            "stop_further_changes": True,
            "assess_state": True,
            "rollback_required_on_verification_failure": True,
            "verify_restored_state": True,
            "incident_evidence_required": True,
            "strategy_ref": "evidence://rollback/strategy-001",
        }
        return {
            "pre_state": pre_state,
            "render_plan": render_plan,
            "sanitized": sanitized,
            "protected": protected,
            "envelope": envelope,
            "lifecycle": lifecycle,
            "profile": profile,
            "management": management,
            "verification": verification,
            "rollback": rollback,
        }

    def _readiness(self, fixture):
        return build_production_transaction_readiness(
            profile=fixture["profile"],
            envelope=fixture["envelope"],
            lifecycle=fixture["lifecycle"],
            backups=[fixture["sanitized"], fixture["protected"]],
            management_path=fixture["management"],
            verification_contract=fixture["verification"],
            rollback_contract=fixture["rollback"],
        ).as_dict()

    def test_readiness_requires_dual_backup_and_vpn_when_enabled(self):
        fixture = self._fixture(wireguard=True)
        readiness = self._readiness(fixture)
        self.assertTrue(readiness["ready"])
        self.assertEqual(
            readiness["backup_kinds"],
            ["protected_ephemeral_binary", "sanitized_export"],
        )
        self.assertEqual(
            readiness["required_verification_checks"],
            ["dns", "management", "routing", "vpn", "wan"],
        )
        self.assertFalse(readiness["transport_present"])
        self.assertFalse(readiness["apply_available"])
        self.assertFalse(readiness["production_writer_available"])
        self.assertFalse(readiness["write_authorized"])

    def test_missing_protected_backup_is_rejected(self):
        fixture = self._fixture()
        with self.assertRaisesRegex(
            ProductionTransactionReadinessError,
            "exactly two pre-change backup evidence records",
        ):
            build_production_transaction_readiness(
                profile=fixture["profile"],
                envelope=fixture["envelope"],
                lifecycle=fixture["lifecycle"],
                backups=[fixture["sanitized"]],
                management_path=fixture["management"],
                verification_contract=fixture["verification"],
                rollback_contract=fixture["rollback"],
            )

    def test_management_monitor_during_apply_is_required(self):
        fixture = self._fixture()
        fixture["management"]["monitor_during_apply"] = False
        with self.assertRaisesRegex(
            ProductionTransactionReadinessError,
            "management readiness is incomplete",
        ):
            self._readiness(fixture)

    def test_runtime_capability_field_is_rejected(self):
        fixture = self._fixture()
        fixture["management"]["url"] = "https://router.example.invalid"
        with self.assertRaisesRegex(
            ProductionTransactionReadinessError,
            "runtime-capability fields",
        ):
            self._readiness(fixture)

    def test_wireguard_profile_requires_vpn_verification_contract(self):
        fixture = self._fixture(wireguard=True)
        fixture["verification"]["checks"].pop("vpn")
        with self.assertRaisesRegex(
            ProductionTransactionReadinessError,
            "missing required check: vpn",
        ):
            self._readiness(fixture)

    def test_verified_outcome_requires_all_checks_to_pass(self):
        fixture = self._fixture(wireguard=False)
        readiness = self._readiness(fixture)
        lifecycle = fixture["lifecycle"]
        lifecycle = transition_transaction_lifecycle(
            lifecycle=lifecycle,
            to_phase="apply_observed",
            evidence={
                "evidence_ref": "evidence://runtime/apply",
                "exact_plan_revalidated": True,
                "exact_pre_state_revalidated": True,
                "backup_revalidated": True,
                "management_path_revalidated": True,
                "connectivity_revalidated": True,
                "apply_completed": True,
            },
        ).as_dict()
        post_state = _sha("post-state")
        lifecycle = transition_transaction_lifecycle(
            lifecycle=lifecycle,
            to_phase="verification_pending",
            evidence={
                "evidence_ref": "evidence://runtime/verification-pending",
                "post_state_sha256": post_state,
            },
        ).as_dict()
        lifecycle = transition_transaction_lifecycle(
            lifecycle=lifecycle,
            to_phase="verified",
            evidence={
                "evidence_ref": "evidence://runtime/verified",
                "management_ok": True,
                "connectivity_ok": True,
                "intended_state_ok": True,
                "post_state_sha256": post_state,
            },
        ).as_dict()
        evidence = {
            "schema_version": "routeros-production-verification-evidence/1",
            "checks": {
                name: {
                    "ok": True,
                    "evidence_ref": f"evidence://post-apply/{name}",
                }
                for name in readiness["required_verification_checks"]
            },
        }
        outcome = evaluate_production_verification_outcome(
            readiness=readiness,
            lifecycle=lifecycle,
            verification_evidence=evidence,
        )
        self.assertEqual(outcome["outcome"], "verified_success")
        self.assertTrue(outcome["deployment_success"])
        self.assertFalse(outcome["failure_recovered"])
        self.assertFalse(outcome["production_writer_available"])
        self.assertFalse(outcome["write_authorized"])

    def test_rolled_back_outcome_is_recovery_not_success(self):
        fixture = self._fixture(wireguard=False)
        readiness = self._readiness(fixture)
        lifecycle = transition_transaction_lifecycle(
            lifecycle=fixture["lifecycle"],
            to_phase="rollback_required",
            evidence={
                "evidence_ref": "evidence://runtime/rollback-required",
                "failure_observed": True,
                "failure_reason_ref": "evidence://runtime/failure-reason",
            },
        ).as_dict()
        lifecycle = transition_transaction_lifecycle(
            lifecycle=lifecycle,
            to_phase="rollback_observed",
            evidence={
                "evidence_ref": "evidence://runtime/rollback-observed",
                "rollback_completed": True,
                "rollback_state_sha256": fixture["pre_state"],
            },
        ).as_dict()
        lifecycle = transition_transaction_lifecycle(
            lifecycle=lifecycle,
            to_phase="rolled_back",
            evidence={
                "evidence_ref": "evidence://runtime/rolled-back",
                "management_recovered": True,
                "connectivity_recovered": True,
                "managed_objects_reconciled": True,
                "rollback_state_sha256": fixture["pre_state"],
            },
        ).as_dict()
        evidence = {
            "schema_version": "routeros-production-verification-evidence/1",
            "checks": {
                name: {
                    "ok": name != "dns",
                    "evidence_ref": f"evidence://failed-verification/{name}",
                }
                for name in readiness["required_verification_checks"]
            },
            "failure_observed": True,
            "recovery": {
                "management_recovered": True,
                "connectivity_recovered": True,
                "managed_objects_reconciled": True,
                "rollback_state_sha256": fixture["pre_state"],
                "evidence_ref": "evidence://recovery/verified",
            },
        }
        outcome = evaluate_production_verification_outcome(
            readiness=readiness,
            lifecycle=lifecycle,
            verification_evidence=evidence,
        )
        self.assertEqual(outcome["outcome"], "failure_recovered")
        self.assertFalse(outcome["deployment_success"])
        self.assertTrue(outcome["failure_recovered"])

    def test_recovery_must_restore_bound_pre_state(self):
        fixture = self._fixture(wireguard=False)
        readiness = self._readiness(fixture)
        lifecycle = transition_transaction_lifecycle(
            lifecycle=fixture["lifecycle"],
            to_phase="rollback_required",
            evidence={
                "evidence_ref": "evidence://runtime/rollback-required",
                "failure_observed": True,
                "failure_reason_ref": "evidence://runtime/failure-reason",
            },
        ).as_dict()
        lifecycle = transition_transaction_lifecycle(
            lifecycle=lifecycle,
            to_phase="rollback_observed",
            evidence={
                "evidence_ref": "evidence://runtime/rollback-observed",
                "rollback_completed": True,
                "rollback_state_sha256": fixture["pre_state"],
            },
        ).as_dict()
        lifecycle = transition_transaction_lifecycle(
            lifecycle=lifecycle,
            to_phase="rolled_back",
            evidence={
                "evidence_ref": "evidence://runtime/rolled-back",
                "management_recovered": True,
                "connectivity_recovered": True,
                "managed_objects_reconciled": True,
                "rollback_state_sha256": fixture["pre_state"],
            },
        ).as_dict()
        evidence = {
            "schema_version": "routeros-production-verification-evidence/1",
            "checks": {
                name: {
                    "ok": False,
                    "evidence_ref": f"evidence://failed-verification/{name}",
                }
                for name in readiness["required_verification_checks"]
            },
            "failure_observed": True,
            "recovery": {
                "management_recovered": True,
                "connectivity_recovered": True,
                "managed_objects_reconciled": True,
                "rollback_state_sha256": _sha("wrong-state"),
                "evidence_ref": "evidence://recovery/invalid",
            },
        }
        with self.assertRaisesRegex(
            ProductionTransactionReadinessError,
            "does not match the bound pre-state digest",
        ):
            evaluate_production_verification_outcome(
                readiness=readiness,
                lifecycle=lifecycle,
                verification_evidence=evidence,
            )


if __name__ == "__main__":
    unittest.main()
