from __future__ import annotations

import copy
import hashlib
import json

import pytest

from router_configuration.transaction_adapter_admission import (
    TransactionAdapterAdmissionError,
    admit_disposable_chr_candidate,
)
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
        backup={
            "ok": True,
            "readable": True,
            "artifact_ref": "backup/pre-change.backup",
            "sha256": "b" * 64,
        },
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


def test_exact_authorized_disposable_chr_candidate_is_admitted_without_writer() -> None:
    plan, envelope, lifecycle, target = _candidate()
    result = admit_disposable_chr_candidate(
        render_plan=plan,
        envelope=envelope,
        lifecycle=lifecycle,
        target=target,
    ).as_dict()
    assert result["claim"] == "eligible_for_disposable_chr_adapter_only"
    assert result["production_writer_available"] is False
    assert result["physical_router_targeted"] is False
    assert result["production_allowed"] is False
    assert result["write_authorized"] is False
    assert result["credentials_present"] is False


def test_direct_adapter_bypass_before_authorization_is_rejected() -> None:
    plan, envelope, _, target = _candidate()
    lifecycle = initialize_transaction_lifecycle(envelope=envelope).as_dict()
    with pytest.raises(TransactionAdapterAdmissionError, match="authorized lifecycle"):
        admit_disposable_chr_candidate(
            render_plan=plan,
            envelope=envelope,
            lifecycle=lifecycle,
            target=target,
        )


def test_tampered_plan_and_cross_transaction_lifecycle_are_rejected() -> None:
    plan, envelope, lifecycle, target = _candidate()
    tampered = copy.deepcopy(plan)
    tampered["render_sha256"] = "f" * 64
    with pytest.raises(TransactionAdapterAdmissionError, match="approved envelope"):
        admit_disposable_chr_candidate(
            render_plan=tampered,
            envelope=envelope,
            lifecycle=lifecycle,
            target=target,
        )

    other_plan, other_envelope, other_lifecycle, _ = _candidate()
    other_envelope = copy.deepcopy(other_envelope)
    other_envelope["transaction_id"] = "e" * 64
    with pytest.raises(TransactionAdapterAdmissionError):
        admit_disposable_chr_candidate(
            render_plan=other_plan,
            envelope=other_envelope,
            lifecycle=other_lifecycle,
            target=target,
        )


def test_physical_production_and_secret_bearing_targets_are_rejected() -> None:
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
        with pytest.raises(TransactionAdapterAdmissionError):
            admit_disposable_chr_candidate(
                render_plan=plan,
                envelope=envelope,
                lifecycle=lifecycle,
                target=variant,
            )
