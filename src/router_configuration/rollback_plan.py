from __future__ import annotations

import hashlib
import hmac
import json
import re
from dataclasses import dataclass
from typing import Any, Iterable, Mapping

from .m02_state_engine import ChangeOperation, ChangePlan
from .ordered_execution import OrderedExecutionPlan
from .types import OperationKind


class RollbackPlanError(ValueError):
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
        raise RollbackPlanError(f"{label} must be a lowercase SHA-256 digest")
    return text


def _reference(value: Any, label: str) -> str:
    text = str(value or "").strip()
    if not text or any(c in text for c in ("\n", "\r", "\x00")):
        raise RollbackPlanError(f"{label} must be a non-empty safe reference")
    return text


def _reject_runtime_fields(value: Mapping[str, Any], label: str) -> None:
    present = sorted(str(key) for key in value if str(key).lower() in _FORBIDDEN)
    if present:
        raise RollbackPlanError(f"{label} contains runtime-capability or secret fields: " + ", ".join(present))


def _verify_signed_payload(value: Mapping[str, Any], digest_field: str, label: str) -> None:
    supplied = _digest(value.get(digest_field), f"{label}.{digest_field}")
    unsigned = dict(value)
    unsigned.pop(digest_field, None)
    if not hmac.compare_digest(supplied, _canonical_sha256(unsigned)):
        raise RollbackPlanError(f"{label} digest mismatch")


def _inverse_kind(kind: OperationKind) -> OperationKind:
    if kind is OperationKind.CREATE:
        return OperationKind.DELETE
    if kind is OperationKind.DELETE:
        return OperationKind.CREATE
    return OperationKind.UPDATE


def _value_sha(value: Any) -> str:
    return _canonical_sha256(value)


@dataclass(frozen=True)
class RollbackPlan:
    payload: Mapping[str, Any]

    def as_dict(self) -> dict[str, Any]:
        return dict(self.payload)


def build_rollback_plan(
    *,
    change_plan: ChangePlan,
    ordered_plan: OrderedExecutionPlan,
    stop_decision: Mapping[str, Any],
    lifecycle: Mapping[str, Any],
    backup_ref: str,
    affected_operation_ids: Iterable[str] | None,
    mutation_scope_confirmed: bool,
) -> RollbackPlan:
    """Build a deterministic non-executable rollback plan.

    Known mutation scope is inverted in strict reverse execution order. If mutation
    scope is uncertain, the only safe strategy is restoring the transaction-bound
    pre-state backup. This module contains no transport, credential resolution,
    automatic rollback or production writer.
    """
    if not isinstance(stop_decision, Mapping) or not isinstance(lifecycle, Mapping):
        raise RollbackPlanError("stop_decision and lifecycle must be objects")
    _reject_runtime_fields(stop_decision, "stop_decision")
    _reject_runtime_fields(lifecycle, "lifecycle")
    _verify_signed_payload(stop_decision, "decision_sha256", "stop_decision")
    _verify_signed_payload(lifecycle, "lifecycle_sha256", "lifecycle")

    if stop_decision.get("decision") != "HALT" or stop_decision.get("rollback_required") is not True:
        raise RollbackPlanError("rollback requires a HALT decision with rollback_required=true")
    if lifecycle.get("schema_version") != "routeros-transaction-lifecycle/1" or lifecycle.get("phase") != "rollback_required":
        raise RollbackPlanError("rollback requires lifecycle phase rollback_required")
    if stop_decision.get("source_plan_id") != ordered_plan.source_plan_id or ordered_plan.source_plan_id != change_plan.plan_id:
        raise RollbackPlanError("rollback inputs are bound to different source plans")
    if stop_decision.get("ordering_sha256") != ordered_plan.ordering_sha256:
        raise RollbackPlanError("rollback stop decision ordering digest mismatch")
    if ordered_plan.apply_available or ordered_plan.transport_present or ordered_plan.write_authorized:
        raise RollbackPlanError("ordered plan must remain non-executable")

    transaction_id = _digest(lifecycle.get("transaction_id"), "lifecycle.transaction_id")
    pre_state_sha = _digest(lifecycle.get("pre_state_sha256"), "lifecycle.pre_state_sha256")
    safe_backup_ref = _reference(backup_ref, "backup_ref")

    order_ids = [step.operation_id for step in ordered_plan.steps]
    by_path: dict[str, ChangeOperation] = {operation.path: operation for operation in change_plan.operations}
    step_by_id = {step.operation_id: step for step in ordered_plan.steps}

    if mutation_scope_confirmed:
        if affected_operation_ids is None:
            raise RollbackPlanError("confirmed mutation scope requires affected_operation_ids")
        affected = [str(item) for item in affected_operation_ids]
        if len(affected) != len(set(affected)):
            raise RollbackPlanError("affected operation ids contain duplicates")
        if affected != order_ids[: len(affected)]:
            raise RollbackPlanError("affected operation ids must be the exact ordered prefix")
        if not affected:
            strategy = "NO_MUTATION_ROLLBACK"
            rollback_steps = []
        else:
            strategy = "INVERSE_CONFIRMED_PREFIX"
            rollback_steps = []
            for rollback_sequence, operation_id in enumerate(reversed(affected), 1):
                step = step_by_id[operation_id]
                operation = by_path.get(step.path)
                if operation is None:
                    raise RollbackPlanError(f"ordered step has no source operation: {step.path}")
                rollback_steps.append({
                    "rollback_sequence": rollback_sequence,
                    "source_operation_id": operation_id,
                    "path": operation.path,
                    "inverse_kind": _inverse_kind(operation.kind).value,
                    "expected_current_value_sha256": _value_sha(operation.after),
                    "restore_value_sha256": _value_sha(operation.before),
                    "risk": int(operation.risk),
                })
    else:
        if affected_operation_ids not in (None, (), []):
            raise RollbackPlanError("uncertain mutation scope must not claim affected operation ids")
        strategy = "RESTORE_BOUND_PRE_STATE_BACKUP"
        affected = []
        rollback_steps = []

    payload: dict[str, Any] = {
        "schema_version": "rollback-plan/1",
        "transaction_id": transaction_id,
        "source_plan_id": change_plan.plan_id,
        "ordering_sha256": ordered_plan.ordering_sha256,
        "pre_state_sha256": pre_state_sha,
        "backup_ref": safe_backup_ref,
        "mutation_scope_confirmed": mutation_scope_confirmed,
        "affected_operation_ids": affected,
        "strategy": strategy,
        "steps": rollback_steps,
        "requires_fresh_post_rollback_verification": True,
        "claim": "deterministic_rollback_plan_only",
        "transport_present": False,
        "apply_available": False,
        "rollback_available": False,
        "production_writer_available": False,
        "write_authorized": False,
    }
    payload["rollback_plan_sha256"] = _canonical_sha256(payload)
    return RollbackPlan(payload)
