from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass
from typing import Any, Mapping, Sequence

_SHA1 = re.compile(r"^[0-9a-f]{40}$")


class ProjectSummaryError(ValueError):
    pass


def _sha256(value: Any) -> str:
    return hashlib.sha256(
        json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False, default=str).encode("utf-8")
    ).hexdigest()


def _strings(values: Sequence[Any], label: str) -> list[str]:
    out = [str(v).strip() for v in values]
    if any(not item for item in out):
        raise ProjectSummaryError(f"{label} contains an empty value")
    return out


@dataclass(frozen=True)
class ProjectSummary:
    payload: Mapping[str, Any]

    def as_dict(self) -> dict[str, Any]:
        return dict(self.payload)


def build_project_summary(
    *,
    project_name: str,
    canonical_total: int,
    completed: int,
    main_sha: str,
    durable_task_ids: Sequence[str],
    next_task_ids: Sequence[str],
    boundaries: Sequence[str],
    evidence_refs: Sequence[str],
) -> ProjectSummary:
    name = str(project_name or "").strip()
    if not name:
        raise ProjectSummaryError("project_name must not be empty")
    if not isinstance(canonical_total, int) or canonical_total <= 0:
        raise ProjectSummaryError("canonical_total must be a positive integer")
    if not isinstance(completed, int) or completed < 0 or completed > canonical_total:
        raise ProjectSummaryError("completed must be within canonical range")
    sha = str(main_sha or "").strip().lower()
    if not _SHA1.fullmatch(sha):
        raise ProjectSummaryError("main_sha must be a lowercase SHA-1 commit id")

    durable = _strings(durable_task_ids, "durable_task_ids")
    if len(durable) != len(set(durable)):
        raise ProjectSummaryError("durable_task_ids must be unique")
    next_ids = _strings(next_task_ids, "next_task_ids")
    bounds = _strings(boundaries, "boundaries")
    refs = _strings(evidence_refs, "evidence_refs")

    remaining = canonical_total - completed
    payload = {
        "schema_version": "omada-project-summary/1",
        "identity": {"project_name": name},
        "durable_progress": {
            "completed": completed,
            "remaining": remaining,
            "total": canonical_total,
            "completion_percent": round(completed * 100 / canonical_total, 2),
        },
        "current_main": sha,
        "completed_scope": durable,
        "next_scope": next_ids,
        "boundaries": bounds,
        "evidence_refs": refs,
        "claim": "durable_project_summary_only",
        "candidate_work_counted": False,
        "transport_present": False,
        "apply_available": False,
        "rollback_available": False,
        "production_writer_available": False,
        "write_authorized": False,
    }
    payload["summary_sha256"] = _sha256(payload)
    return ProjectSummary(payload)
