from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from typing import Any, Iterable, Mapping

from .ordered_execution import OrderedExecutionPlan


class StopOnFailureError(ValueError):
    pass


_FORBIDDEN = frozenset({
    "url", "username", "password", "credential", "credential_ref", "token",
    "secret", "private_key", "transport", "method", "shell", "command", "commands",
})


def _canonical_sha256(value: Any) -> str:
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(",", ":"), default=str).encode("utf-8")).hexdigest()


def _evidence_ref(value: Any) -> str:
    text = str(value or "").strip()
    if not text or any(c in text for c in ("\n", "\r", "\x00")):
        raise StopOnFailureError("evidence_ref must be a non-empty safe reference")
    return text


def _reject_runtime_fields(evidence: Mapping[str, Any]) -> None:
    present = sorted(str(k) for k in evidence if str(k).lower() in _FORBIDDEN)
    if present:
        raise StopOnFailureError("observation contains runtime-capability or secret fields: " + ", ".join(present))


@dataclass(frozen=True)
class StopOnFailureDecision:
    payload: Mapping[str, Any]

    def as_dict(self) -> dict[str, Any]:
        return dict(self.payload)


def evaluate_execution_checkpoint(
    *,
    plan: OrderedExecutionPlan,
    completed_operation_ids: Iterable[str],
    observation: Mapping[str, Any],
) -> StopOnFailureDecision:
    """Advance exactly one ordered step or halt deterministically on failure.

    This is an audit/control decision only. It cannot execute the operation or rollback.
    """
    if not isinstance(observation, Mapping):
        raise StopOnFailureError("observation must be an object")
    _reject_runtime_fields(observation)
    evidence_ref = _evidence_ref(observation.get("evidence_ref"))

    all_ids = [step.operation_id for step in plan.steps]
    completed = [str(item) for item in completed_operation_ids]
    if len(completed) != len(set(completed)):
        raise StopOnFailureError("completed operation ids contain duplicates")
    if completed != all_ids[: len(completed)]:
        raise StopOnFailureError("completed operation ids must be the exact ordered prefix")
    if len(completed) >= len(all_ids):
        raise StopOnFailureError("ordered execution plan has no remaining operation")

    expected_id = all_ids[len(completed)]
    observed_id = str(observation.get("operation_id") or "").strip()
    if observed_id != expected_id:
        raise StopOnFailureError("observation is not for the next ordered operation")
    if type(observation.get("apply_ok")) is not bool or type(observation.get("verification_ok")) is not bool:
        raise StopOnFailureError("apply_ok and verification_ok must be explicit booleans")

    failed = not observation["apply_ok"] or not observation["verification_ok"]
    next_id = None if failed or len(completed) + 1 >= len(all_ids) else all_ids[len(completed) + 1]
    payload = {
        "schema_version": "stop-on-failure/1",
        "source_plan_id": plan.source_plan_id,
        "ordering_sha256": plan.ordering_sha256,
        "observed_operation_id": expected_id,
        "evidence_ref": evidence_ref,
        "completed_prefix_before": completed,
        "apply_ok": observation["apply_ok"],
        "verification_ok": observation["verification_ok"],
        "decision": "HALT" if failed else ("COMPLETE" if next_id is None else "ADVANCE"),
        "halt_forward_progress": failed,
        "rollback_required": failed,
        "next_operation_id": next_id,
        "transport_present": False,
        "apply_available": False,
        "rollback_available": False,
        "production_writer_available": False,
        "write_authorized": False,
    }
    payload["decision_sha256"] = _canonical_sha256(payload)
    return StopOnFailureDecision(payload)
