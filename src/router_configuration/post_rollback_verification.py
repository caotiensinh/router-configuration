from __future__ import annotations

import hashlib
import hmac
import json
import re
from dataclasses import dataclass
from typing import Any, Mapping

from .readback_verification import ReadBackVerificationError, build_readback_verification


class PostRollbackVerificationError(ValueError):
    pass


_SHA256 = re.compile(r"^[0-9a-f]{64}$")
_FORBIDDEN = frozenset({
    "url", "router_url", "username", "password", "credential", "credential_ref",
    "token", "secret", "private_key", "transport", "method", "shell", "command", "commands",
})


def _canonical_sha256(value: Any) -> str:
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False, default=str).encode("utf-8")).hexdigest()


def _digest(value: Any, label: str) -> str:
    text = str(value or "").strip().lower()
    if not _SHA256.fullmatch(text):
        raise PostRollbackVerificationError(f"{label} must be a lowercase SHA-256 digest")
    return text


def _reference(value: Any, label: str) -> str:
    text = str(value or "").strip()
    if not text or any(c in text for c in ("\n", "\r", "\x00")):
        raise PostRollbackVerificationError(f"{label} must be a non-empty safe reference")
    return text


def _verify_lifecycle(lifecycle: Mapping[str, Any]) -> tuple[str, str]:
    if lifecycle.get("schema_version") != "routeros-transaction-lifecycle/1":
        raise PostRollbackVerificationError("unsupported transaction lifecycle schema")
    if lifecycle.get("phase") != "rollback_observed":
        raise PostRollbackVerificationError("post-rollback verification requires lifecycle phase rollback_observed")
    for field in ("transport_present", "apply_available", "rollback_available", "production_writer_available", "write_authorized", "secret_values_present"):
        if lifecycle.get(field) is not False:
            raise PostRollbackVerificationError(f"lifecycle must keep {field}=false")
    supplied = _digest(lifecycle.get("lifecycle_sha256"), "lifecycle.lifecycle_sha256")
    unsigned = dict(lifecycle); unsigned.pop("lifecycle_sha256", None)
    if not hmac.compare_digest(supplied, _canonical_sha256(unsigned)):
        raise PostRollbackVerificationError("lifecycle digest mismatch")
    return _digest(lifecycle.get("transaction_id"), "lifecycle.transaction_id"), _digest(lifecycle.get("pre_state_sha256"), "lifecycle.pre_state_sha256")


def _reject_runtime_fields(value: Mapping[str, Any], label: str) -> None:
    present = sorted(str(k) for k in value if str(k).lower() in _FORBIDDEN)
    if present:
        raise PostRollbackVerificationError(f"{label} contains runtime-capability or secret fields: {', '.join(present)}")


@dataclass(frozen=True)
class PostRollbackVerification:
    payload: Mapping[str, Any]
    def as_dict(self) -> dict[str, Any]:
        return dict(self.payload)


def build_post_rollback_verification(
    *,
    lifecycle: Mapping[str, Any],
    pre_state_managed_state: Mapping[str, Any],
    rollback_readback_managed_state: Mapping[str, Any],
    evidence: Mapping[str, Any],
) -> PostRollbackVerification:
    """Verify recovery from an independently acquired fresh read-back.

    This function is audit-only. It does not execute rollback or contact a device.
    It reuses the generic read-back verifier against the bound pre-state projection,
    then emits evidence suitable for a later lifecycle transition to `rolled_back`.
    """
    if not isinstance(lifecycle, Mapping) or not isinstance(evidence, Mapping):
        raise PostRollbackVerificationError("lifecycle and evidence must be objects")
    _reject_runtime_fields(evidence, "evidence")
    transaction_id, pre_state_sha = _verify_lifecycle(lifecycle)
    if _digest(evidence.get("transaction_id"), "evidence.transaction_id") != transaction_id:
        raise PostRollbackVerificationError("evidence is bound to a different transaction")
    if _digest(evidence.get("pre_state_sha256"), "evidence.pre_state_sha256") != pre_state_sha:
        raise PostRollbackVerificationError("evidence pre-state digest does not match lifecycle")
    if evidence.get("management_recovered") is not True or evidence.get("connectivity_recovered") is not True:
        raise PostRollbackVerificationError("management_recovered and connectivity_recovered must be true")
    evidence_ref = _reference(evidence.get("evidence_ref"), "evidence.evidence_ref")

    try:
        readback = build_readback_verification(
            source_plan_id=transaction_id,
            desired_managed_state=pre_state_managed_state,
            readback_managed_state=rollback_readback_managed_state,
            evidence={
                "evidence_ref": evidence_ref,
                "fresh_read": evidence.get("fresh_read"),
                "independently_acquired": evidence.get("independently_acquired"),
                "apply_observation_reused": evidence.get("apply_observation_reused"),
            },
        ).as_dict()
    except ReadBackVerificationError as exc:
        raise PostRollbackVerificationError(str(exc)) from exc

    reconciled = readback["acceptance"] == "PASS"
    payload = {
        "schema_version": "post-rollback-verification/1",
        "transaction_id": transaction_id,
        "pre_state_sha256": pre_state_sha,
        "evidence_ref": evidence_ref,
        "fresh_read": True,
        "independently_acquired": True,
        "management_recovered": True,
        "connectivity_recovered": True,
        "managed_objects_reconciled": reconciled,
        "readback_verification_sha256": readback["verification_sha256"],
        "drift_count": readback["drift_count"],
        "drift": readback["drift"],
        "acceptance": "PASS" if reconciled else "FAIL",
        "lifecycle_transition_evidence": {
            "evidence_ref": evidence_ref,
            "management_recovered": True,
            "connectivity_recovered": True,
            "managed_objects_reconciled": reconciled,
            "rollback_state_sha256": pre_state_sha if reconciled else readback["readback_state_sha256"],
        },
        "claim": "independent_post_rollback_verification_only",
        "transport_present": False,
        "apply_available": False,
        "rollback_available": False,
        "production_writer_available": False,
        "write_authorized": False,
    }
    payload["post_rollback_verification_sha256"] = _canonical_sha256(payload)
    return PostRollbackVerification(payload)
