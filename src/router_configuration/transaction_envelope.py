from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass
from typing import Any, Mapping

from .transaction_backup_evidence import (
    TransactionBackupEvidenceError,
    validate_transaction_backup_evidence,
)


class TransactionEnvelopeError(ValueError):
    pass


_SHA256 = re.compile(r"^[0-9a-f]{64}$")


def _canonical_sha256(payload: Mapping[str, Any]) -> str:
    canonical = json.dumps(
        payload,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        default=str,
    ).encode("utf-8")
    return hashlib.sha256(canonical).hexdigest()


def _sha256(value: Any, label: str) -> str:
    text = str(value or "").strip().lower()
    if not _SHA256.fullmatch(text):
        raise TransactionEnvelopeError(f"{label} must be a lowercase SHA-256 digest")
    return text


def _ref(value: Any, label: str) -> str:
    text = str(value or "").strip()
    if not text:
        raise TransactionEnvelopeError(f"{label} must not be empty")
    if any(character in text for character in ("\n", "\r", "\x00")):
        raise TransactionEnvelopeError(f"{label} contains unsupported control characters")
    return text


def _verify_render_plan(plan: Mapping[str, Any]) -> str:
    if plan.get("transport_present") is not False:
        raise TransactionEnvelopeError("render plan must not contain a transport")
    if plan.get("apply_available") is not False:
        raise TransactionEnvelopeError("render plan must keep apply unavailable")
    if plan.get("write_authorized") is not False:
        raise TransactionEnvelopeError("render plan must keep write_authorized=false")
    supplied = _sha256(plan.get("render_sha256"), "render_plan.render_sha256")
    unsigned = dict(plan)
    unsigned.pop("render_sha256", None)
    expected = _canonical_sha256(unsigned)
    if supplied != expected:
        raise TransactionEnvelopeError("render plan digest mismatch")
    return supplied


@dataclass(frozen=True)
class TransactionEnvelope:
    payload: Mapping[str, Any]

    def as_dict(self) -> dict[str, Any]:
        return dict(self.payload)


def build_transaction_envelope(
    *,
    render_plan: Mapping[str, Any],
    pre_state_sha256: str,
    backup: Mapping[str, Any],
    approval: Mapping[str, Any],
    management_path: Mapping[str, Any],
    connectivity_baseline: Mapping[str, Any],
) -> TransactionEnvelope:
    """Bind immutable pre-apply evidence without exposing a write transport.

    This is a planning boundary only. A future adapter may consume an accepted
    envelope, but this module has no credentials, router URL, mutation method or
    secret resolution capability.
    """

    render_sha = _verify_render_plan(render_plan)
    state_sha = _sha256(pre_state_sha256, "pre_state_sha256")

    try:
        validate_transaction_backup_evidence(
            backup,
            expected_pre_state_sha256=state_sha,
        )
    except TransactionBackupEvidenceError as exc:
        raise TransactionEnvelopeError("backup evidence verification failed") from exc
    backup_binding = dict(backup)

    if approval.get("approved") is not True:
        raise TransactionEnvelopeError("approval.approved must be explicitly true")
    approval_plan_sha = _sha256(
        approval.get("plan_sha256"),
        "approval.plan_sha256",
    )
    if approval_plan_sha != render_sha:
        raise TransactionEnvelopeError("approval is not bound to the exact render plan")
    approver_ref = _ref(approval.get("approver_ref"), "approval.approver_ref")

    if management_path.get("ok") is not True:
        raise TransactionEnvelopeError("management path evidence must pass")
    management_ref = _ref(
        management_path.get("evidence_ref"),
        "management_path.evidence_ref",
    )
    if connectivity_baseline.get("ok") is not True:
        raise TransactionEnvelopeError("connectivity baseline evidence must pass")
    connectivity_ref = _ref(
        connectivity_baseline.get("evidence_ref"),
        "connectivity_baseline.evidence_ref",
    )

    bindings = {
        "render_plan_sha256": render_sha,
        "pre_state_sha256": state_sha,
        "backup": backup_binding,
        "approval": {
            "approved": True,
            "plan_sha256": approval_plan_sha,
            "approver_ref": approver_ref,
        },
        "management_path": {
            "ok": True,
            "evidence_ref": management_ref,
        },
        "connectivity_baseline": {
            "ok": True,
            "evidence_ref": connectivity_ref,
        },
    }
    transaction_id = _canonical_sha256(bindings)
    payload = {
        "schema_version": "routeros-transaction-envelope/1",
        "transaction_id": transaction_id,
        "claim": "prepared_for_future_authorized_adapter",
        "bindings": bindings,
        "required_runtime_order": [
            "revalidate_exact_plan_and_pre_state",
            "revalidate_backup",
            "revalidate_management_path",
            "apply_exact_approved_plan",
            "verify_management_and_connectivity",
            "verify_intended_state",
            "rollback_on_any_failed_verification",
            "verify_recovery",
        ],
        "secret_values_present": False,
        "transport_present": False,
        "apply_available": False,
        "production_writer_available": False,
        "write_authorized": False,
    }
    payload["envelope_sha256"] = _canonical_sha256(payload)
    return TransactionEnvelope(payload)
