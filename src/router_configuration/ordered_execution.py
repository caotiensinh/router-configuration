from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from typing import Any, Iterable, Mapping

from .m02_state_engine import ChangeOperation, ChangePlan
from .types import OperationKind


class OrderedExecutionError(ValueError):
    pass


def _canonical_sha256(value: Any) -> str:
    return hashlib.sha256(
        json.dumps(value, sort_keys=True, separators=(",", ":"), default=str).encode("utf-8")
    ).hexdigest()


def _operation_id(plan_id: str, operation: ChangeOperation) -> str:
    return _canonical_sha256(
        {
            "plan_id": plan_id,
            "path": operation.path,
            "kind": operation.kind.value,
            "before": operation.before,
            "after": operation.after,
            "risk": int(operation.risk),
        }
    )[:20]


@dataclass(frozen=True)
class OrderedExecutionStep:
    sequence: int
    operation_id: str
    path: str
    kind: OperationKind
    risk: int
    depends_on: tuple[str, ...]


@dataclass(frozen=True)
class OrderedExecutionPlan:
    source_plan_id: str
    steps: tuple[OrderedExecutionStep, ...]
    ordering_sha256: str
    apply_available: bool = False
    transport_present: bool = False
    write_authorized: bool = False


def build_ordered_execution_plan(
    change_plan: ChangePlan,
    *,
    dependencies: Mapping[str, Iterable[str]] | None = None,
) -> OrderedExecutionPlan:
    """Create a deterministic, dependency-safe mutation order without executing it.

    Dependency keys and values are ChangeOperation paths. Explicit dependencies always
    win. Among currently-ready operations, conservative deterministic tie-breaking runs
    lower-risk work first and DELETE last. Unknown dependencies, self-dependencies and
    dependency cycles fail closed. This module contains no transport or write capability.
    """

    operations = tuple(change_plan.operations)
    by_path: dict[str, ChangeOperation] = {}
    for operation in operations:
        if operation.path in by_path:
            raise OrderedExecutionError(f"duplicate operation path: {operation.path}")
        by_path[operation.path] = operation

    raw_dependencies = dependencies or {}
    unknown_keys = sorted(set(raw_dependencies) - set(by_path))
    if unknown_keys:
        raise OrderedExecutionError("dependency declared for unknown operation: " + ", ".join(unknown_keys))

    required: dict[str, set[str]] = {path: set() for path in by_path}
    for path, prerequisite_paths in raw_dependencies.items():
        for prerequisite in prerequisite_paths:
            prerequisite = str(prerequisite)
            if prerequisite not in by_path:
                raise OrderedExecutionError(
                    f"operation {path} depends on unknown operation: {prerequisite}"
                )
            if prerequisite == path:
                raise OrderedExecutionError(f"operation cannot depend on itself: {path}")
            required[path].add(prerequisite)

    operation_ids = {
        path: _operation_id(change_plan.plan_id, operation)
        for path, operation in by_path.items()
    }
    kind_rank = {
        OperationKind.CREATE: 0,
        OperationKind.UPDATE: 1,
        OperationKind.DELETE: 2,
    }

    remaining = set(by_path)
    completed: set[str] = set()
    steps: list[OrderedExecutionStep] = []

    while remaining:
        ready = [path for path in remaining if required[path] <= completed]
        if not ready:
            cycle_members = ", ".join(sorted(remaining))
            raise OrderedExecutionError(f"dependency cycle or unsatisfied dependency set: {cycle_members}")

        ready.sort(
            key=lambda path: (
                int(by_path[path].risk),
                kind_rank[by_path[path].kind],
                path,
                operation_ids[path],
            )
        )
        path = ready[0]
        operation = by_path[path]
        steps.append(
            OrderedExecutionStep(
                sequence=len(steps) + 1,
                operation_id=operation_ids[path],
                path=path,
                kind=operation.kind,
                risk=int(operation.risk),
                depends_on=tuple(sorted(operation_ids[item] for item in required[path])),
            )
        )
        remaining.remove(path)
        completed.add(path)

    digest_payload = [
        {
            "sequence": step.sequence,
            "operation_id": step.operation_id,
            "path": step.path,
            "kind": step.kind.value,
            "risk": step.risk,
            "depends_on": list(step.depends_on),
        }
        for step in steps
    ]
    return OrderedExecutionPlan(
        source_plan_id=change_plan.plan_id,
        steps=tuple(steps),
        ordering_sha256=_canonical_sha256(
            {"source_plan_id": change_plan.plan_id, "steps": digest_payload}
        ),
    )
