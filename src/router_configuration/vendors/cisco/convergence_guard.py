"""Deterministic convergence guard for parallel Cisco development lanes.

The guard validates lane metadata before a convergence batch is assembled. It
never updates refs or merges branches; it prevents stale-base, overlapping-file,
failed-check, or write-authority lanes from being treated as merge candidates.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass
import hashlib
import json
import re
from typing import Iterable

_GIT_SHA_RE = re.compile(r"^[0-9a-f]{40}$")
_LANE_ID_RE = re.compile(r"^[A-Za-z0-9_.:-]{1,96}$")


class CiscoConvergenceGuardError(ValueError):
    """Raised when parallel lane metadata is unsafe to converge."""


def _canonical_sha256(value: object) -> str:
    raw = json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("utf-8")
    return hashlib.sha256(raw).hexdigest()


@dataclass(frozen=True)
class CiscoLaneCandidate:
    lane_id: str
    base_sha: str
    head_sha: str
    owned_paths: tuple[str, ...]
    required_checks_passed: bool
    production_write_authorized: bool = False

    def as_dict(self) -> dict:
        payload = asdict(self)
        payload["owned_paths"] = list(self.owned_paths)
        return payload


@dataclass(frozen=True)
class CiscoConvergenceManifest:
    base_sha: str
    lane_ids: tuple[str, ...]
    head_shas: tuple[str, ...]
    owned_paths: tuple[str, ...]
    manifest_sha256: str
    convergence_candidate: bool = True
    repository_merge_performed: bool = False
    parent_ref_updated: bool = False
    production_write_authorized: bool = False

    def as_dict(self) -> dict:
        payload = asdict(self)
        payload["lane_ids"] = list(self.lane_ids)
        payload["head_shas"] = list(self.head_shas)
        payload["owned_paths"] = list(self.owned_paths)
        payload["schema_version"] = "cisco-parallel-convergence-manifest/1"
        return payload


def _clean_path(value: str) -> str:
    path = str(value).strip().replace("\\", "/")
    if not path or path.startswith("/") or ".." in path.split("/") or path.endswith("/"):
        raise CiscoConvergenceGuardError(f"invalid owned path: {value!r}")
    return path


def build_convergence_manifest(
    lanes: Iterable[CiscoLaneCandidate],
    *,
    expected_base_sha: str,
) -> CiscoConvergenceManifest:
    candidates = tuple(lanes)
    if len(candidates) < 2:
        raise CiscoConvergenceGuardError("convergence batch requires at least two independent lanes")
    base = str(expected_base_sha).strip().lower()
    if not _GIT_SHA_RE.fullmatch(base):
        raise CiscoConvergenceGuardError("expected base must be an exact 40-character Git SHA")

    lane_ids: set[str] = set()
    heads: set[str] = set()
    path_owner: dict[str, str] = {}
    normalized: list[CiscoLaneCandidate] = []
    for lane in candidates:
        lane_id = lane.lane_id.strip()
        if not _LANE_ID_RE.fullmatch(lane_id) or lane_id in lane_ids:
            raise CiscoConvergenceGuardError("lane id is invalid or duplicated")
        lane_ids.add(lane_id)
        lane_base = lane.base_sha.strip().lower()
        head = lane.head_sha.strip().lower()
        if lane_base != base:
            raise CiscoConvergenceGuardError(f"stale or different base for lane: {lane_id}")
        if not _GIT_SHA_RE.fullmatch(head) or head == base or head in heads:
            raise CiscoConvergenceGuardError(f"invalid or duplicated head SHA for lane: {lane_id}")
        heads.add(head)
        if lane.required_checks_passed is not True:
            raise CiscoConvergenceGuardError(f"required checks are not PASS for lane: {lane_id}")
        if lane.production_write_authorized:
            raise CiscoConvergenceGuardError(f"lane unexpectedly carries production write authority: {lane_id}")
        paths = tuple(sorted({_clean_path(path) for path in lane.owned_paths}))
        if not paths:
            raise CiscoConvergenceGuardError(f"lane has no owned paths: {lane_id}")
        for path in paths:
            if path in path_owner:
                raise CiscoConvergenceGuardError(
                    f"owned path conflict: {path} belongs to both {path_owner[path]} and {lane_id}"
                )
            path_owner[path] = lane_id
        normalized.append(CiscoLaneCandidate(lane_id, base, head, paths, True, False))

    normalized.sort(key=lambda item: item.lane_id)
    unsigned = {
        "schema_version": "cisco-parallel-convergence-manifest/1",
        "base_sha": base,
        "lanes": [item.as_dict() for item in normalized],
        "convergence_candidate": True,
        "repository_merge_performed": False,
        "parent_ref_updated": False,
        "production_write_authorized": False,
    }
    return CiscoConvergenceManifest(
        base_sha=base,
        lane_ids=tuple(item.lane_id for item in normalized),
        head_shas=tuple(item.head_sha for item in normalized),
        owned_paths=tuple(sorted(path_owner)),
        manifest_sha256=_canonical_sha256(unsigned),
    )
