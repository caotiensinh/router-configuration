"""Deterministic 500-lane planning primitives for repository work.

This module does not spawn workers. It computes conflict-free execution waves
for independently executing workers and keeps vendor technical truth outside
the orchestration layer.
"""

from __future__ import annotations

import argparse
from dataclasses import dataclass
import json
from pathlib import PurePosixPath
import re
from typing import Iterable, Mapping, Sequence

MAX_LANES = 500
LANE_PREFIX = "LANE"
_SHA_RE = re.compile(r"^[0-9a-f]{40}$")
_TASK_ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$")
_CONFLICT_KEY_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:/-]{0,127}$")


class LaneContractError(ValueError):
    """Raised when a task set or lane manifest violates the orchestration contract."""


@dataclass(frozen=True)
class LaneTask:
    task_id: str
    mode: str
    write_paths: tuple[str, ...]
    dependencies: tuple[str, ...] = ()
    conflict_keys: tuple[str, ...] = ()
    priority: int = 0


@dataclass(frozen=True)
class LaneAssignment:
    lane_id: str
    task_id: str
    mode: str
    write_paths: tuple[str, ...]
    conflict_keys: tuple[str, ...]


def lane_id(index: int) -> str:
    if not isinstance(index, int) or isinstance(index, bool) or not 1 <= index <= MAX_LANES:
        raise LaneContractError(f"lane index must be between 1 and {MAX_LANES}")
    return f"{LANE_PREFIX}-{index:04d}"


def lane_ids(count: int = MAX_LANES) -> tuple[str, ...]:
    if not isinstance(count, int) or isinstance(count, bool) or not 1 <= count <= MAX_LANES:
        raise LaneContractError(f"lane count must be between 1 and {MAX_LANES}")
    return tuple(lane_id(index) for index in range(1, count + 1))


def _normalize_repo_path(value: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise LaneContractError("repository paths must be non-empty strings")
    raw = value.strip().replace("\\", "/")
    if raw.startswith("/") or re.match(r"^[A-Za-z]:/", raw):
        raise LaneContractError(f"absolute repository path is forbidden: {value!r}")
    path = PurePosixPath(raw)
    if any(part in {"", ".", ".."} for part in path.parts):
        raise LaneContractError(f"repository path traversal/ambiguity is forbidden: {value!r}")
    normalized = str(path)
    if normalized == "." or normalized.startswith("../"):
        raise LaneContractError(f"repository path escapes the repository: {value!r}")
    return normalized


def _normalize_str_tuple(
    values: Iterable[str],
    *,
    field: str,
    pattern: re.Pattern[str] | None = None,
) -> tuple[str, ...]:
    normalized: list[str] = []
    for value in values:
        if not isinstance(value, str):
            raise LaneContractError(f"{field} entries must be strings")
        item = value.strip()
        if not item:
            raise LaneContractError(f"{field} entries must not be empty")
        if pattern is not None and not pattern.fullmatch(item):
            raise LaneContractError(f"invalid {field} entry: {value!r}")
        normalized.append(item)
    if len(normalized) != len(set(normalized)):
        raise LaneContractError(f"{field} entries must be unique")
    return tuple(sorted(normalized))


def task_from_mapping(value: Mapping[str, object]) -> LaneTask:
    task_id_value = value.get("task_id")
    if not isinstance(task_id_value, str) or not _TASK_ID_RE.fullmatch(task_id_value.strip()):
        raise LaneContractError("task_id must match the repository lane task identifier contract")
    task_id_value = task_id_value.strip()

    mode = value.get("mode", "write")
    if mode not in {"read_only", "write"}:
        raise LaneContractError(f"unsupported task mode for {task_id_value}: {mode!r}")

    raw_paths = value.get("write_paths", [])
    if not isinstance(raw_paths, list):
        raise LaneContractError(f"write_paths must be a list for {task_id_value}")
    write_paths = tuple(sorted({_normalize_repo_path(str(item)) for item in raw_paths}))
    if mode == "write" and not write_paths:
        raise LaneContractError(f"write task {task_id_value} must declare write_paths")
    if mode == "read_only" and write_paths:
        raise LaneContractError(f"read-only task {task_id_value} must not declare write_paths")

    raw_dependencies = value.get("dependencies", [])
    if not isinstance(raw_dependencies, list):
        raise LaneContractError(f"dependencies must be a list for {task_id_value}")
    dependencies = _normalize_str_tuple(
        (str(item) for item in raw_dependencies),
        field="dependencies",
        pattern=_TASK_ID_RE,
    )

    raw_conflicts = value.get("conflict_keys", [])
    if not isinstance(raw_conflicts, list):
        raise LaneContractError(f"conflict_keys must be a list for {task_id_value}")
    conflict_keys = _normalize_str_tuple(
        (str(item) for item in raw_conflicts),
        field="conflict_keys",
        pattern=_CONFLICT_KEY_RE,
    )

    priority = value.get("priority", 0)
    if not isinstance(priority, int) or isinstance(priority, bool):
        raise LaneContractError(f"priority must be an integer for {task_id_value}")

    return LaneTask(
        task_id=task_id_value,
        mode=mode,
        write_paths=write_paths,
        dependencies=dependencies,
        conflict_keys=conflict_keys,
        priority=priority,
    )


def _paths_conflict(left: str, right: str) -> bool:
    return left == right or left.startswith(right + "/") or right.startswith(left + "/")


def tasks_conflict(left: LaneTask, right: LaneTask) -> bool:
    if set(left.conflict_keys).intersection(right.conflict_keys):
        return True
    if left.mode == "read_only" or right.mode == "read_only":
        return False
    return any(_paths_conflict(a, b) for a in left.write_paths for b in right.write_paths)


def _validate_task_graph(tasks: Sequence[LaneTask]) -> dict[str, LaneTask]:
    by_id: dict[str, LaneTask] = {}
    for task in tasks:
        if task.task_id in by_id:
            raise LaneContractError(f"duplicate task_id: {task.task_id}")
        by_id[task.task_id] = task

    known = set(by_id)
    for task in tasks:
        unknown = sorted(set(task.dependencies) - known)
        if unknown:
            raise LaneContractError(
                f"task {task.task_id} depends on unknown task(s): {', '.join(unknown)}"
            )
        if task.task_id in task.dependencies:
            raise LaneContractError(f"task {task.task_id} cannot depend on itself")
    return by_id


def plan_parallel_waves(
    tasks: Sequence[LaneTask],
    *,
    max_lanes: int = MAX_LANES,
) -> tuple[tuple[LaneAssignment, ...], ...]:
    if not isinstance(max_lanes, int) or isinstance(max_lanes, bool):
        raise LaneContractError("max_lanes must be an integer")
    if not 1 <= max_lanes <= MAX_LANES:
        raise LaneContractError(f"max_lanes must be between 1 and {MAX_LANES}")

    remaining = _validate_task_graph(tasks)
    completed: set[str] = set()
    waves: list[tuple[LaneAssignment, ...]] = []

    while remaining:
        ready = [
            task
            for task in remaining.values()
            if set(task.dependencies).issubset(completed)
        ]
        if not ready:
            blocked = ", ".join(sorted(remaining))
            raise LaneContractError(f"dependency cycle or unsatisfied graph detected: {blocked}")

        ready.sort(key=lambda task: (-task.priority, task.task_id))
        selected: list[LaneTask] = []
        for candidate in ready:
            if len(selected) >= max_lanes:
                break
            if any(tasks_conflict(candidate, existing) for existing in selected):
                continue
            selected.append(candidate)

        if not selected:
            raise LaneContractError("scheduler could not select a runnable task")

        assignments = tuple(
            LaneAssignment(
                lane_id=lane_id(index),
                task_id=task.task_id,
                mode=task.mode,
                write_paths=task.write_paths,
                conflict_keys=task.conflict_keys,
            )
            for index, task in enumerate(selected, start=1)
        )
        waves.append(assignments)
        for task in selected:
            completed.add(task.task_id)
            del remaining[task.task_id]

    return tuple(waves)


def plan_document(
    task_document: Mapping[str, object],
    *,
    max_lanes: int = MAX_LANES,
    base_sha: str | None = None,
) -> dict[str, object]:
    raw_tasks = task_document.get("tasks")
    if not isinstance(raw_tasks, list):
        raise LaneContractError("task document must contain a tasks list")
    tasks = tuple(task_from_mapping(item) for item in raw_tasks if isinstance(item, Mapping))
    if len(tasks) != len(raw_tasks):
        raise LaneContractError("every task entry must be an object")

    if base_sha is None:
        candidate = task_document.get("base_sha")
        base_sha = candidate if isinstance(candidate, str) else None
    if base_sha is not None:
        base_sha = base_sha.strip().lower()
        if not _SHA_RE.fullmatch(base_sha):
            raise LaneContractError("base_sha must be a lowercase 40-character Git SHA")

    waves = plan_parallel_waves(tasks, max_lanes=max_lanes)
    return {
        "schema_version": "parallel-lane-plan/1",
        "base_sha": base_sha,
        "lane_capacity": MAX_LANES,
        "requested_max_lanes": max_lanes,
        "worker_processes_started": 0,
        "capacity_is_not_worker_count": True,
        "waves": [
            {
                "wave": wave_index,
                "assignments": [
                    {
                        "lane_id": assignment.lane_id,
                        "task_id": assignment.task_id,
                        "mode": assignment.mode,
                        "write_paths": list(assignment.write_paths),
                        "conflict_keys": list(assignment.conflict_keys),
                    }
                    for assignment in wave
                ],
            }
            for wave_index, wave in enumerate(waves, start=1)
        ],
    }


def validate_capacity_manifest(document: Mapping[str, object]) -> None:
    if document.get("schema_version") != "parallel-lane-capacity/1":
        raise LaneContractError("unsupported lane-capacity schema")
    if document.get("lane_capacity") != MAX_LANES:
        raise LaneContractError(f"lane_capacity must be exactly {MAX_LANES}")
    ids = document.get("lane_ids")
    if ids != list(lane_ids()):
        raise LaneContractError("lane_ids must contain exactly LANE-0001 through LANE-0500")
    if document.get("capacity_is_not_worker_count") is not True:
        raise LaneContractError("manifest must distinguish lane capacity from active workers")
    if document.get("direct_main_write") is not False:
        raise LaneContractError("parallel lanes must not authorize direct main writes")
    if document.get("vendor_truth_authority") != "validated_vendor_knowledge_only":
        raise LaneContractError("lane scheduler must not become a vendor technical authority")


def _load_json(path: str) -> dict[str, object]:
    with open(path, "r", encoding="utf-8") as handle:
        value = json.load(handle)
    if not isinstance(value, dict):
        raise LaneContractError("JSON document root must be an object")
    return value


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Plan or validate repository parallel lanes")
    subparsers = parser.add_subparsers(dest="command", required=True)

    validate_parser = subparsers.add_parser("validate-capacity")
    validate_parser.add_argument("--manifest", required=True)

    plan_parser = subparsers.add_parser("plan")
    plan_parser.add_argument("--tasks", required=True)
    plan_parser.add_argument("--output", required=True)
    plan_parser.add_argument("--max-lanes", type=int, default=MAX_LANES)
    plan_parser.add_argument("--base-sha")

    args = parser.parse_args(argv)
    if args.command == "validate-capacity":
        validate_capacity_manifest(_load_json(args.manifest))
        return 0

    document = plan_document(
        _load_json(args.tasks),
        max_lanes=args.max_lanes,
        base_sha=args.base_sha,
    )
    with open(args.output, "w", encoding="utf-8") as handle:
        json.dump(document, handle, indent=2, sort_keys=True)
        handle.write("\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
