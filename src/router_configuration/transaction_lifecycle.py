from __future__ import annotations

import hashlib
import hmac
import json
import re
from dataclasses import dataclass
from typing import Any, Mapping


class TransactionLifecycleError(ValueError):
    pass


_SHA256 = re.compile(r"^[0-9a-f]{64}$")
_ALLOWED_PHASES = {
    "prepared",
    "authorized",
    "apply_observed",
    "verification_pending",
    "verified",
    "rollback_required",
    "rollback_observed",
    "rolled_back",
}
_ALLOWED_TRANSITIONS = {
    "prepared": {"authorized"},
    "authorized": {"apply_observed", "rollback_required"},
    "apply_observed": {"verification_pending", "rollback_required"},
    "verification_pending": {"verified", "rollback_required"},
    "verified": set(),
    "rollback_required": {"rollback_observed"},
    "rollback_observed": {"rolled_back"},
    "rolled_back": set(),
}


def _canonical_sha256(value: Any) -> str:
    encoded = json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        default=str,
    ).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def _digest(value: Any, label: str) -> str:
    text = str(value or "").strip().lower()
    if not _SHA256.fullmatch(text):
        raise TransactionLifecycleError(f"{label} must be a lowercase SHA-256 digest")
    return text


def _reference(value: Any, label: str) -> str:
    text = str(value or "").strip()
    if not text:
        raise TransactionLifecycleError(f"{label} must not be empty")
    if any(character in text for character in ("\n", "\r", "\x00")):
        raise TransactionLifecycleError(f"{label} contains unsupported control characters")
    return text


def _assert_no_runtime_capability(value: Mapping[str, Any], label: str) -> None:
    forbidden = {
        "url",
        "router_url",
        "username",
        "password",
        "credential",
        "credential_ref",
        "token",
        "secret",
        "private_key",
        "transport",
        "method",
        "shell",
        "command",
        "commands",
    }
    present = sorted(str(key) for key in value if str(key).lower() in forbidden)
    if present:
        raise TransactionLifecycleError(
            f"{label} contains runtime-capability fields: {', '.join(present)}"
        )


def _verify_envelope(envelope: Mapping[str, Any]) -> tuple[str, str, str]:
    if envelope.get("schema_version") != "routeros-transaction-envelope/1":
        raise TransactionLifecycleError("unsupported transaction envelope schema")
    if envelope.get("transport_present") is not False:
        raise TransactionLifecycleError("transaction envelope must not contain a transport")
    if envelope.get("apply_available") is not False:
        raise TransactionLifecycleError("transaction envelope must keep apply unavailable")
    if envelope.get("production_writer_available") is not False:
        raise TransactionLifecycleError("transaction envelope must keep production writer unavailable")
    if envelope.get("write_authorized") is not False:
        raise TransactionLifecycleError("transaction envelope must keep write_authorized=false")

    envelope_sha = _digest(envelope.get("envelope_sha256"), "envelope.envelope_sha256")
    unsigned = dict(envelope)
    unsigned.pop("envelope_sha256", None)
    if not hmac.compare_digest(envelope_sha, _canonical_sha256(unsigned)):
        raise TransactionLifecycleError("transaction envelope digest mismatch")

    transaction_id = _digest(envelope.get("transaction_id"), "envelope.transaction_id")
    bindings = envelope.get("bindings")
    if not isinstance(bindings, Mapping):
        raise TransactionLifecycleError("transaction envelope bindings must be an object")
    pre_state_sha = _digest(bindings.get("pre_state_sha256"), "bindings.pre_state_sha256")
    return transaction_id, envelope_sha, pre_state_sha


def _event_digest(
    *,
    transaction_id: str,
    sequence: int,
    from_phase: str,
    to_phase: str,
    evidence: Mapping[str, Any],
    previous_event_sha256: str | None,
) -> str:
    payload = {
        "transaction_id": transaction_id,
        "sequence": sequence,
        "from_phase": from_phase,
        "to_phase": to_phase,
        "evidence": dict(evidence),
        "previous_event_sha256": previous_event_sha256,
    }
    return _canonical_sha256(payload)


@dataclass(frozen=True)
class TransactionLifecycle:
    payload: Mapping[str, Any]

    def as_dict(self) -> dict[str, Any]:
        return dict(self.payload)


def initialize_transaction_lifecycle(
    *,
    envelope: Mapping[str, Any],
) -> TransactionLifecycle:
    """Create a pure audit state machine from an accepted transaction envelope.

    This module deliberately cannot contact or mutate RouterOS. It records only
    evidence-bound lifecycle transitions for a future separately-authorized
    runtime adapter.
    """

    transaction_id, envelope_sha, pre_state_sha = _verify_envelope(envelope)
    payload = {
        "schema_version": "routeros-transaction-lifecycle/1",
        "transaction_id": transaction_id,
        "envelope_sha256": envelope_sha,
        "pre_state_sha256": pre_state_sha,
        "phase": "prepared",
        "sequence": 0,
        "events": [],
        "claim": "audit_state_only",
        "secret_values_present": False,
        "transport_present": False,
        "apply_available": False,
        "rollback_available": False,
        "production_writer_available": False,
        "write_authorized": False,
    }
    payload["lifecycle_sha256"] = _canonical_sha256(payload)
    return TransactionLifecycle(payload)


def _verify_lifecycle(lifecycle: Mapping[str, Any]) -> None:
    if lifecycle.get("schema_version") != "routeros-transaction-lifecycle/1":
        raise TransactionLifecycleError("unsupported transaction lifecycle schema")
    for field in (
        "transport_present",
        "apply_available",
        "rollback_available",
        "production_writer_available",
        "write_authorized",
        "secret_values_present",
    ):
        if lifecycle.get(field) is not False:
            raise TransactionLifecycleError(f"transaction lifecycle must keep {field}=false")
    phase = str(lifecycle.get("phase") or "")
    if phase not in _ALLOWED_PHASES:
        raise TransactionLifecycleError("transaction lifecycle phase is invalid")
    supplied = _digest(lifecycle.get("lifecycle_sha256"), "lifecycle.lifecycle_sha256")
    unsigned = dict(lifecycle)
    unsigned.pop("lifecycle_sha256", None)
    if not hmac.compare_digest(supplied, _canonical_sha256(unsigned)):
        raise TransactionLifecycleError("transaction lifecycle digest mismatch")


def _require_true(evidence: Mapping[str, Any], keys: tuple[str, ...], label: str) -> None:
    missing = [key for key in keys if evidence.get(key) is not True]
    if missing:
        raise TransactionLifecycleError(
            f"{label} requires explicit true evidence: {', '.join(missing)}"
        )


def transition_transaction_lifecycle(
    *,
    lifecycle: Mapping[str, Any],
    to_phase: str,
    evidence: Mapping[str, Any],
) -> TransactionLifecycle:
    """Append one deterministic evidence-bound lifecycle transition.

    `evidence` may contain only references, digests and booleans. Runtime
    capabilities such as URLs, credentials, methods or commands are rejected.
    """

    _verify_lifecycle(lifecycle)
    if not isinstance(evidence, Mapping):
        raise TransactionLifecycleError("transition evidence must be an object")
    _assert_no_runtime_capability(evidence, "transition evidence")

    current = str(lifecycle.get("phase") or "")
    target = str(to_phase or "").strip()
    if target not in _ALLOWED_TRANSITIONS[current]:
        raise TransactionLifecycleError(f"invalid lifecycle transition: {current} -> {target}")

    transaction_id = _digest(lifecycle.get("transaction_id"), "lifecycle.transaction_id")
    pre_state_sha = _digest(lifecycle.get("pre_state_sha256"), "lifecycle.pre_state_sha256")
    _reference(evidence.get("evidence_ref"), "evidence.evidence_ref")

    if target == "authorized":
        _require_true(evidence, ("authorized", "exact_envelope_revalidated"), "authorization")
        if _digest(evidence.get("transaction_id"), "evidence.transaction_id") != transaction_id:
            raise TransactionLifecycleError("authorization is bound to a different transaction")
    elif target == "apply_observed":
        _require_true(
            evidence,
            (
                "exact_plan_revalidated",
                "exact_pre_state_revalidated",
                "backup_revalidated",
                "management_path_revalidated",
                "connectivity_revalidated",
                "apply_completed",
            ),
            "apply observation",
        )
    elif target == "verification_pending":
        _digest(evidence.get("post_state_sha256"), "evidence.post_state_sha256")
    elif target == "verified":
        _require_true(
            evidence,
            ("management_ok", "connectivity_ok", "intended_state_ok"),
            "verification",
        )
        _digest(evidence.get("post_state_sha256"), "evidence.post_state_sha256")
    elif target == "rollback_required":
        if evidence.get("failure_observed") is not True:
            raise TransactionLifecycleError("rollback_required requires failure_observed=true")
        _reference(evidence.get("failure_reason_ref"), "evidence.failure_reason_ref")
    elif target == "rollback_observed":
        _require_true(evidence, ("rollback_completed",), "rollback observation")
        _digest(evidence.get("rollback_state_sha256"), "evidence.rollback_state_sha256")
    elif target == "rolled_back":
        _require_true(
            evidence,
            ("management_recovered", "connectivity_recovered", "managed_objects_reconciled"),
            "rollback verification",
        )
        rollback_sha = _digest(
            evidence.get("rollback_state_sha256"),
            "evidence.rollback_state_sha256",
        )
        if not hmac.compare_digest(rollback_sha, pre_state_sha):
            raise TransactionLifecycleError(
                "rolled_back requires rollback_state_sha256 to equal the bound pre-state digest"
            )

    sequence = int(lifecycle.get("sequence", 0)) + 1
    events = lifecycle.get("events")
    if not isinstance(events, list):
        raise TransactionLifecycleError("transaction lifecycle events must be a list")
    previous = None
    if events:
        last = events[-1]
        if not isinstance(last, Mapping):
            raise TransactionLifecycleError("transaction lifecycle contains an invalid event")
        previous = _digest(last.get("event_sha256"), "events[-1].event_sha256")

    normalized_evidence = dict(evidence)
    event_sha = _event_digest(
        transaction_id=transaction_id,
        sequence=sequence,
        from_phase=current,
        to_phase=target,
        evidence=normalized_evidence,
        previous_event_sha256=previous,
    )
    event = {
        "sequence": sequence,
        "from_phase": current,
        "to_phase": target,
        "evidence": normalized_evidence,
        "previous_event_sha256": previous,
        "event_sha256": event_sha,
    }

    payload = dict(lifecycle)
    payload["phase"] = target
    payload["sequence"] = sequence
    payload["events"] = [*events, event]
    payload.pop("lifecycle_sha256", None)
    payload["lifecycle_sha256"] = _canonical_sha256(payload)
    return TransactionLifecycle(payload)
