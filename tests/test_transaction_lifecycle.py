import hashlib
import json
import unittest

from router_configuration.transaction_backup_evidence import build_transaction_backup_evidence
from router_configuration.transaction_envelope import build_transaction_envelope
from router_configuration.transaction_lifecycle import (
    TransactionLifecycleError,
    initialize_transaction_lifecycle,
    transition_transaction_lifecycle,
)


def canonical_sha(payload):
    return hashlib.sha256(
        json.dumps(
            payload,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=False,
        ).encode("utf-8")
    ).hexdigest()


def envelope():
    plan = {
        "schema_version": "routeros-render-plan/1",
        "commands": [],
        "blocked_operations": [],
        "transport_present": False,
        "apply_available": False,
        "write_authorized": False,
    }
    plan["render_sha256"] = canonical_sha(plan)
    return build_transaction_envelope(
        render_plan=plan,
        pre_state_sha256="a" * 64,
        backup=build_transaction_backup_evidence(
            kind="sanitized_export",
            artifact_ref="artifact://chr/pre-change.rsc",
            sha256="b" * 64,
            pre_state_sha256="a" * 64,
        ).as_dict(),
        approval={
            "approved": True,
            "plan_sha256": plan["render_sha256"],
            "approver_ref": "approval/change-001",
        },
        management_path={"ok": True, "evidence_ref": "evidence/management.json"},
        connectivity_baseline={"ok": True, "evidence_ref": "evidence/connectivity.json"},
    ).as_dict()


def authorize(lifecycle):
    return transition_transaction_lifecycle(
        lifecycle=lifecycle,
        to_phase="authorized",
        evidence={
            "evidence_ref": "evidence/runtime-authorization.json",
            "authorized": True,
            "exact_envelope_revalidated": True,
            "transaction_id": lifecycle["transaction_id"],
        },
    ).as_dict()


def observe_apply(lifecycle):
    return transition_transaction_lifecycle(
        lifecycle=lifecycle,
        to_phase="apply_observed",
        evidence={
            "evidence_ref": "evidence/apply-observation.json",
            "exact_plan_revalidated": True,
            "exact_pre_state_revalidated": True,
            "backup_revalidated": True,
            "management_path_revalidated": True,
            "connectivity_revalidated": True,
            "apply_completed": True,
        },
    ).as_dict()


class TransactionLifecycleTests(unittest.TestCase):
    def test_verified_path_is_deterministic_and_audit_only(self):
        first = initialize_transaction_lifecycle(envelope=envelope()).as_dict()
        second = initialize_transaction_lifecycle(envelope=envelope()).as_dict()
        self.assertEqual(first, second)
        self.assertEqual(first["phase"], "prepared")
        self.assertFalse(first["transport_present"])
        self.assertFalse(first["apply_available"])
        self.assertFalse(first["rollback_available"])
        self.assertFalse(first["production_writer_available"])
        self.assertFalse(first["write_authorized"])

        current = authorize(first)
        current = observe_apply(current)
        current = transition_transaction_lifecycle(
            lifecycle=current,
            to_phase="verification_pending",
            evidence={
                "evidence_ref": "evidence/post-state.json",
                "post_state_sha256": "c" * 64,
            },
        ).as_dict()
        current = transition_transaction_lifecycle(
            lifecycle=current,
            to_phase="verified",
            evidence={
                "evidence_ref": "evidence/verification.json",
                "management_ok": True,
                "connectivity_ok": True,
                "intended_state_ok": True,
                "post_state_sha256": "c" * 64,
            },
        ).as_dict()

        self.assertEqual(current["phase"], "verified")
        self.assertEqual(current["sequence"], 4)
        self.assertEqual(len(current["events"]), 4)
        for index, event in enumerate(current["events"]):
            self.assertEqual(event["sequence"], index + 1)
            self.assertEqual(len(event["event_sha256"]), 64)
            if index == 0:
                self.assertIsNone(event["previous_event_sha256"])
            else:
                self.assertEqual(
                    event["previous_event_sha256"],
                    current["events"][index - 1]["event_sha256"],
                )

    def test_failure_path_requires_exact_pre_state_before_rolled_back(self):
        current = authorize(initialize_transaction_lifecycle(envelope=envelope()).as_dict())
        current = observe_apply(current)
        current = transition_transaction_lifecycle(
            lifecycle=current,
            to_phase="rollback_required",
            evidence={
                "evidence_ref": "evidence/failure.json",
                "failure_observed": True,
                "failure_reason_ref": "finding/connectivity-regressed",
            },
        ).as_dict()
        current = transition_transaction_lifecycle(
            lifecycle=current,
            to_phase="rollback_observed",
            evidence={
                "evidence_ref": "evidence/rollback-apply.json",
                "rollback_completed": True,
                "rollback_state_sha256": "d" * 64,
            },
        ).as_dict()

        with self.assertRaisesRegex(TransactionLifecycleError, "bound pre-state"):
            transition_transaction_lifecycle(
                lifecycle=current,
                to_phase="rolled_back",
                evidence={
                    "evidence_ref": "evidence/rollback-verify.json",
                    "management_recovered": True,
                    "connectivity_recovered": True,
                    "managed_objects_reconciled": True,
                    "rollback_state_sha256": "d" * 64,
                },
            )

        rolled_back = transition_transaction_lifecycle(
            lifecycle=current,
            to_phase="rolled_back",
            evidence={
                "evidence_ref": "evidence/rollback-verify.json",
                "management_recovered": True,
                "connectivity_recovered": True,
                "managed_objects_reconciled": True,
                "rollback_state_sha256": "a" * 64,
            },
        ).as_dict()
        self.assertEqual(rolled_back["phase"], "rolled_back")

    def test_invalid_transition_is_rejected(self):
        current = initialize_transaction_lifecycle(envelope=envelope()).as_dict()
        with self.assertRaisesRegex(TransactionLifecycleError, "invalid lifecycle transition"):
            transition_transaction_lifecycle(
                lifecycle=current,
                to_phase="verified",
                evidence={"evidence_ref": "evidence/nope.json"},
            )

    def test_authorization_must_bind_exact_transaction(self):
        current = initialize_transaction_lifecycle(envelope=envelope()).as_dict()
        with self.assertRaisesRegex(TransactionLifecycleError, "different transaction"):
            transition_transaction_lifecycle(
                lifecycle=current,
                to_phase="authorized",
                evidence={
                    "evidence_ref": "evidence/auth.json",
                    "authorized": True,
                    "exact_envelope_revalidated": True,
                    "transaction_id": "f" * 64,
                },
            )

    def test_runtime_capability_fields_are_rejected(self):
        current = initialize_transaction_lifecycle(envelope=envelope()).as_dict()
        with self.assertRaisesRegex(TransactionLifecycleError, "runtime-capability"):
            transition_transaction_lifecycle(
                lifecycle=current,
                to_phase="authorized",
                evidence={
                    "evidence_ref": "evidence/auth.json",
                    "authorized": True,
                    "exact_envelope_revalidated": True,
                    "transaction_id": current["transaction_id"],
                    "url": "http://127.0.0.1/rest",
                },
            )

    def test_tampered_lifecycle_digest_is_rejected(self):
        current = initialize_transaction_lifecycle(envelope=envelope()).as_dict()
        current["phase"] = "authorized"
        with self.assertRaisesRegex(TransactionLifecycleError, "digest mismatch"):
            transition_transaction_lifecycle(
                lifecycle=current,
                to_phase="apply_observed",
                evidence={"evidence_ref": "evidence/apply.json"},
            )

    def test_rollback_required_needs_explicit_failure(self):
        current = authorize(initialize_transaction_lifecycle(envelope=envelope()).as_dict())
        with self.assertRaisesRegex(TransactionLifecycleError, "failure_observed"):
            transition_transaction_lifecycle(
                lifecycle=current,
                to_phase="rollback_required",
                evidence={
                    "evidence_ref": "evidence/failure.json",
                    "failure_observed": False,
                    "failure_reason_ref": "finding/unknown",
                },
            )


if __name__ == "__main__":
    unittest.main()
