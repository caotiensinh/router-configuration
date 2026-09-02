from __future__ import annotations

import copy
import hashlib
import json
import unittest

from router_configuration.transaction_adapter_admission import (
    TransactionAdapterAdmissionError,
    admit_disposable_chr_candidate,
)
from router_configuration.transaction_backup_evidence import build_transaction_backup_evidence
from router_configuration.transaction_envelope import build_transaction_envelope
from router_configuration.transaction_lifecycle import (
    initialize_transaction_lifecycle,
    transition_transaction_lifecycle,
)


def _sha(payload: dict) -> str:
    return hashlib.sha256(
        json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()
    ).hexdigest()


def _candidate():
    plan = {
        "schema_version": "routeros-render-plan/1",
        "commands": [],
        "blocked_operations": [],
        "transport_present": False,
        "apply_available": False,
        "write_authorized": False,
    }
    plan["render_sha256"] = _sha(plan)
    envelope = build_transaction_envelope(
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
    lifecycle = initialize_transaction_lifecycle(envelope=envelope).as_dict()
    lifecycle = transition_transaction_lifecycle(
        lifecycle=lifecycle,
        to_phase="authorized",
        evidence={
            "evidence_ref": "evidence/runtime-authorization.json",
            "authorized": True,
            "exact_envelope_revalidated": True,
            "transaction_id": lifecycle["transaction_id"],
        },
    ).as_dict()
    target = {
        "target_kind": "disposable_chr",
        "disposable": True,
        "snapshot_mode": True,
        "physical_router_targeted": False,
        "production": False,
    }
    return plan, envelope, lifecycle, target


class TransactionAdapterAdmissionTests(unittest.TestCase):
    def test_exact_authorized_disposable_chr_candidate_is_admitted_without_writer(self):
        plan, envelope, lifecycle, target = _candidate()
        result = admit_disposable_chr_candidate(
            render_plan=plan,
            envelope=envelope,
            lifecycle=lifecycle,
            target=target,
        ).as_dict()
        self.assertEqual(result["claim"], "eligible_for_disposable_chr_adapter_only")
        self.assertFalse(result["production_writer_available"])
        self.assertFalse(result["physical_router_targeted"])
        self.assertFalse(result["production_allowed"])
        self.assertFalse(result["write_authorized"])
        self.assertFalse(result["credentials_present"])

    def test_direct_adapter_bypass_before_authorization_is_rejected(self):
        plan, envelope, _, target = _candidate()
        lifecycle = initialize_transaction_lifecycle(envelope=envelope).as_dict()
        with self.assertRaisesRegex(TransactionAdapterAdmissionError, "authorized lifecycle"):
            admit_disposable_chr_candidate(
                render_plan=plan,
                envelope=envelope,
                lifecycle=lifecycle,
                target=target,
            )

    def test_tampered_plan_and_cross_transaction_lifecycle_are_rejected(self):
        plan, envelope, lifecycle, target = _candidate()
        tampered = copy.deepcopy(plan)
        tampered["render_sha256"] = "f" * 64
        with self.assertRaisesRegex(TransactionAdapterAdmissionError, "approved envelope"):
            admit_disposable_chr_candidate(
                render_plan=tampered,
                envelope=envelope,
                lifecycle=lifecycle,
                target=target,
            )

        other_plan, other_envelope, other_lifecycle, _ = _candidate()
        other_envelope = copy.deepcopy(other_envelope)
        other_envelope["transaction_id"] = "e" * 64
        with self.assertRaises(TransactionAdapterAdmissionError):
            admit_disposable_chr_candidate(
                render_plan=other_plan,
                envelope=other_envelope,
                lifecycle=other_lifecycle,
                target=target,
            )

    def test_physical_production_and_secret_bearing_targets_are_rejected(self):
        plan, envelope, lifecycle, target = _candidate()
        variants = []
        physical = copy.deepcopy(target)
        physical["physical_router_targeted"] = True
        variants.append(physical)
        production = copy.deepcopy(target)
        production["production"] = True
        variants.append(production)
        secret = copy.deepcopy(target)
        secret["password"] = "forbidden"
        variants.append(secret)

        for variant in variants:
            with self.subTest(variant=variant):
                with self.assertRaises(TransactionAdapterAdmissionError):
                    admit_disposable_chr_candidate(
                        render_plan=plan,
                        envelope=envelope,
                        lifecycle=lifecycle,
                        target=variant,
                    )


if __name__ == "__main__":
    unittest.main()
