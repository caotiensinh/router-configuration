from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass
from typing import Any, Iterable, Mapping, Sequence

from .m02_state_engine import ChangePlan
from .ordered_execution import build_ordered_execution_plan
from .types import RiskLevel

_SHA1 = re.compile(r"^[0-9a-f]{40}$")


class ImplementationPlanError(ValueError):
    pass


def _sha256(value: Any) -> str:
    return hashlib.sha256(
        json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False, default=str).encode("utf-8")
    ).hexdigest()


def _required_text(value: str | None, label: str) -> str:
    text = str(value or "").strip()
    if not text:
        raise ImplementationPlanError(f"{label} is required")
    return text


def _refs(values: Sequence[str], label: str) -> tuple[str, ...]:
    normalized = tuple(str(v).strip() for v in values)
    if not normalized or any(not item for item in normalized):
        raise ImplementationPlanError(f"{label} must contain non-empty evidence references")
    if len(set(normalized)) != len(normalized):
        raise ImplementationPlanError(f"{label} must be unique")
    return normalized


@dataclass(frozen=True)
class ImplementationPlan:
    payload: Mapping[str, Any]

    def as_dict(self) -> dict[str, Any]:
        return dict(self.payload)


def build_implementation_plan(
    change_plan: ChangePlan,
    *,
    current_main_sha: str,
    dependencies: Mapping[str, Iterable[str]] | None = None,
    evidence_refs: Sequence[str],
    change_window: str | None = None,
    backup_ref: str | None = None,
    rollback_ref: str | None = None,
) -> ImplementationPlan:
    sha = str(current_main_sha or "").strip().lower()
    if not _SHA1.fullmatch(sha):
        raise ImplementationPlanError("current_main_sha must be a lowercase SHA-1 commit id")

    refs = _refs(evidence_refs, "evidence_refs")
    ordered = build_ordered_execution_plan(change_plan, dependencies=dependencies)
    high_risk = any(step.risk >= int(RiskLevel.NETWORK_CHANGE) for step in ordered.steps)

    if high_risk:
        window = _required_text(change_window, "change_window")
        backup = _required_text(backup_ref, "backup_ref")
        rollback = _required_text(rollback_ref, "rollback_ref")
    else:
        window = str(change_window or "").strip() or None
        backup = str(backup_ref or "").strip() or None
        rollback = str(rollback_ref or "").strip() or None

    steps = [
        {
            "sequence": step.sequence,
            "operation_id": step.operation_id,
            "path": step.path,
            "kind": step.kind.value,
            "risk": step.risk,
            "depends_on": list(step.depends_on),
        }
        for step in ordered.steps
    ]
    payload = {
        "schema_version": "omada-implementation-plan/1",
        "source_change_plan_id": change_plan.plan_id,
        "source_ordering_sha256": ordered.ordering_sha256,
        "current_main_sha": sha,
        "steps": steps,
        "risk_controls": {
            "high_risk_change": high_risk,
            "change_window": window,
            "backup_ref": backup,
            "rollback_ref": rollback,
            "stop_on_failure_required": True,
            "fresh_readback_required_after_each_mutation": True,
            "final_desired_vs_actual_validation_required": True,
        },
        "evidence_refs": list(refs),
        "claim": "deterministic_non_executable_implementation_plan",
        "transport_present": False,
        "apply_available": False,
        "rollback_available": False,
        "production_writer_available": False,
        "write_authorized": False,
    }
    payload["implementation_plan_sha256"] = _sha256(payload)
    return ImplementationPlan(payload)
