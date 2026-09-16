from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from typing import Any, Mapping

from .m02_state_engine import StateEngine


class ReadBackVerificationError(ValueError):
    pass


_FORBIDDEN_EVIDENCE_FIELDS = frozenset(
    {
        "password",
        "credential",
        "credential_ref",
        "token",
        "secret",
        "private_key",
        "command",
        "commands",
        "method",
        "transport",
        "shell",
    }
)


def _canonical_sha256(value: Any) -> str:
    encoded = json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        default=str,
    ).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def _reference(value: Any, label: str) -> str:
    text = str(value or "").strip()
    if not text:
        raise ReadBackVerificationError(f"{label} must not be empty")
    if any(character in text for character in ("\n", "\r", "\x00")):
        raise ReadBackVerificationError(f"{label} contains unsupported control characters")
    return text


def _verify_evidence(evidence: Mapping[str, Any]) -> str:
    present = sorted(
        str(key)
        for key in evidence
        if str(key).lower() in _FORBIDDEN_EVIDENCE_FIELDS
    )
    if present:
        raise ReadBackVerificationError(
            "read-back evidence contains runtime-capability or secret fields: "
            + ", ".join(present)
        )
    if evidence.get("fresh_read") is not True:
        raise ReadBackVerificationError("read-back verification requires fresh_read=true")
    if evidence.get("independently_acquired") is not True:
        raise ReadBackVerificationError(
            "read-back verification requires independently_acquired=true"
        )
    if evidence.get("apply_observation_reused") is not False:
        raise ReadBackVerificationError(
            "read-back verification requires apply_observation_reused=false"
        )
    return _reference(evidence.get("evidence_ref"), "evidence.evidence_ref")


@dataclass(frozen=True)
class ReadBackVerification:
    payload: Mapping[str, Any]

    def as_dict(self) -> dict[str, Any]:
        return dict(self.payload)


def build_readback_verification(
    *,
    source_plan_id: str,
    desired_managed_state: Mapping[str, Any],
    readback_managed_state: Mapping[str, Any],
    evidence: Mapping[str, Any],
) -> ReadBackVerification:
    """Compare normalized desired state with an independently acquired read-back.

    This function is deliberately non-executable. Vendor adapters are responsible
    for acquiring and normalizing fresh state. The verifier consumes only the
    managed-state projection, then reuses StateEngine to produce deterministic
    drift evidence. It never accepts the apply observation as verification state.
    """

    plan_id = _reference(source_plan_id, "source_plan_id")
    if not isinstance(desired_managed_state, Mapping):
        raise ReadBackVerificationError("desired_managed_state must be an object")
    if not isinstance(readback_managed_state, Mapping):
        raise ReadBackVerificationError("readback_managed_state must be an object")
    if not isinstance(evidence, Mapping):
        raise ReadBackVerificationError("evidence must be an object")

    evidence_ref = _verify_evidence(evidence)
    drift = StateEngine().build_plan(desired_managed_state, readback_managed_state)
    drift_items = [
        {
            "path": operation.path,
            "kind": operation.kind.value,
            "before": operation.before,
            "after": operation.after,
            "risk": int(operation.risk),
        }
        for operation in drift.operations
    ]

    exact_match = drift.is_noop
    payload: dict[str, Any] = {
        "schema_version": "readback-verification/1",
        "source_plan_id": plan_id,
        "evidence_ref": evidence_ref,
        "fresh_read": True,
        "independently_acquired": True,
        "apply_observation_reused": False,
        "desired_state_sha256": _canonical_sha256(desired_managed_state),
        "readback_state_sha256": _canonical_sha256(readback_managed_state),
        "readback_matches_desired": exact_match,
        "drift_plan_id": drift.plan_id,
        "drift_count": len(drift_items),
        "drift": drift_items,
        "verification_state": "VERIFIED" if exact_match else "MISMATCH",
        "acceptance": "PASS" if exact_match else "FAIL",
        "claim": "independent_managed_state_readback_only",
        "secret_values_present": False,
        "transport_present": False,
        "apply_available": False,
        "production_writer_available": False,
        "write_authorized": False,
    }
    payload["verification_sha256"] = _canonical_sha256(payload)
    return ReadBackVerification(payload)
