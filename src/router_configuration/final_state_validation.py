from __future__ import annotations

import hashlib
import hmac
import json
import re
from dataclasses import dataclass
from typing import Any, Mapping

from .readback_verification import ReadBackVerificationError, build_readback_verification
from .transaction_lifecycle import TransactionLifecycleError, _verify_lifecycle


class FinalStateValidationError(ValueError):
    pass


_SHA256 = re.compile(r"^[0-9a-f]{64}$")
_FORBIDDEN = frozenset({
    "url", "router_url", "username", "password", "credential", "credential_ref",
    "token", "secret", "private_key", "transport", "method", "shell", "command", "commands",
})


def _canonical_sha256(value: Any) -> str:
    return hashlib.sha256(
        json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False, default=str).encode("utf-8")
    ).hexdigest()


def _digest(value: Any, label: str) -> str:
    text = str(value or "").strip().lower()
    if not _SHA256.fullmatch(text):
        raise FinalStateValidationError(f"{label} must be a lowercase SHA-256 digest")
    return text


def _reference(value: Any, label: str) -> str:
    text = str(value or "").strip()
    if not text or any(c in text for c in ("\n", "\r", "\x00")):
        raise FinalStateValidationError(f"{label} must be a non-empty safe reference")
    return text


def _reject_runtime_fields(value: Mapping[str, Any], label: str) -> None:
    present = sorted(str(k) for k in value if str(k).lower() in _FORBIDDEN)
    if present:
        raise FinalStateValidationError(
            f"{label} contains runtime-capability or secret fields: {', '.join(present)}"
        )


@dataclass(frozen=True)
class FinalStateValidation:
    payload: Mapping[str, Any]

    def as_dict(self) -> dict[str, Any]:
        return dict(self.payload)


def build_final_state_validation(
    *,
    lifecycle: Mapping[str, Any],
    desired_managed_state: Mapping[str, Any],
    final_readback_managed_state: Mapping[str, Any],
    evidence: Mapping[str, Any],
) -> FinalStateValidation:
    """Validate final desired-vs-actual state without execution capability.

    A successful desired-state deployment must already be in lifecycle phase
    `verified`. A rolled-back transaction is recovery, not desired-state success.
    This validator performs a fresh independent final read-back comparison and
    binds operational checks to the same transaction.
    """
    if not isinstance(lifecycle, Mapping) or not isinstance(evidence, Mapping):
        raise FinalStateValidationError("lifecycle and evidence must be objects")
    _reject_runtime_fields(evidence, "evidence")
    try:
        _verify_lifecycle(lifecycle)
    except TransactionLifecycleError as exc:
        raise FinalStateValidationError("transaction lifecycle verification failed") from exc

    phase = str(lifecycle.get("phase") or "")
    if phase != "verified":
        if phase == "rolled_back":
            raise FinalStateValidationError(
                "rolled_back is verified recovery, not desired-state deployment success"
            )
        raise FinalStateValidationError("final desired-state validation requires lifecycle phase verified")

    transaction_id = _digest(lifecycle.get("transaction_id"), "lifecycle.transaction_id")
    if _digest(evidence.get("transaction_id"), "evidence.transaction_id") != transaction_id:
        raise FinalStateValidationError("final evidence is bound to a different transaction")

    required_true = ("management_ok", "connectivity_ok", "intended_behavior_ok", "negative_controls_ok")
    missing = [key for key in required_true if evidence.get(key) is not True]
    if missing:
        raise FinalStateValidationError(
            "final operational evidence requires explicit true: " + ", ".join(missing)
        )
    evidence_ref = _reference(evidence.get("evidence_ref"), "evidence.evidence_ref")

    try:
        readback = build_readback_verification(
            source_plan_id=transaction_id,
            desired_managed_state=desired_managed_state,
            readback_managed_state=final_readback_managed_state,
            evidence={
                "evidence_ref": evidence_ref,
                "fresh_read": evidence.get("fresh_read"),
                "independently_acquired": evidence.get("independently_acquired"),
                "apply_observation_reused": evidence.get("apply_observation_reused"),
            },
        ).as_dict()
    except ReadBackVerificationError as exc:
        raise FinalStateValidationError(str(exc)) from exc

    exact = readback["acceptance"] == "PASS"
    payload = {
        "schema_version": "final-desired-actual-validation/1",
        "transaction_id": transaction_id,
        "evidence_ref": evidence_ref,
        "lifecycle_phase": "verified",
        "fresh_read": True,
        "independently_acquired": True,
        "management_ok": True,
        "connectivity_ok": True,
        "intended_behavior_ok": True,
        "negative_controls_ok": True,
        "desired_matches_actual": exact,
        "drift_count": readback["drift_count"],
        "drift": readback["drift"],
        "readback_verification_sha256": readback["verification_sha256"],
        "acceptance": "PASS" if exact else "FAIL",
        "claim": "final_desired_vs_actual_validation_only",
        "transport_present": False,
        "apply_available": False,
        "rollback_available": False,
        "production_writer_available": False,
        "write_authorized": False,
    }
    payload["final_validation_sha256"] = _canonical_sha256(payload)
    return FinalStateValidation(payload)
