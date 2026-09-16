"""Fail-closed pre-handover readiness for Cisco IOS XE C12 review.

This module summarizes canonical C06-C11 prerequisites. It may declare a bundle
ready for C12 human review, but it never completes C12 or grants production write
authority.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass
import hashlib
import json
import re
from typing import Mapping

_REQUIRED_STAGES = ("C06", "C07", "C08", "C09", "C10", "C11")
_SHA256_RE = re.compile(r"^[0-9a-f]{64}$")


class CiscoHandoverReadinessError(ValueError):
    """Raised when handover-readiness input is malformed or unsafe."""


def _canonical_sha256(value: object) -> str:
    raw = json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("utf-8")
    return hashlib.sha256(raw).hexdigest()


@dataclass(frozen=True)
class CiscoHandoverReadiness:
    required_stages: tuple[str, ...]
    completed_stages: tuple[str, ...]
    blockers: tuple[str, ...]
    evidence_bundle_sha256: str
    readiness_sha256: str
    physical_device_verified: bool
    ready_for_c12_human_review: bool
    c12_complete: bool = False
    production_writer_available: bool = False
    production_write_authorized: bool = False

    def as_dict(self) -> dict:
        payload = asdict(self)
        payload["required_stages"] = list(self.required_stages)
        payload["completed_stages"] = list(self.completed_stages)
        payload["blockers"] = list(self.blockers)
        payload["schema_version"] = "cisco-c12-pre-handover-readiness/1"
        return payload


def assess_c12_handover_readiness(
    *,
    stage_complete: Mapping[str, bool],
    evidence_sha256: Mapping[str, str],
    physical_device_verified: bool,
    production_writer_available: bool = False,
    production_write_authorized: bool = False,
) -> CiscoHandoverReadiness:
    """Assess C12 review readiness without completing C12 or enabling writes."""

    if production_writer_available or production_write_authorized:
        raise CiscoHandoverReadinessError("pre-handover readiness cannot carry production write capability or authority")
    if set(stage_complete) != set(_REQUIRED_STAGES):
        raise CiscoHandoverReadinessError("stage_complete must contain exactly C06 through C11")
    if set(evidence_sha256) != set(_REQUIRED_STAGES):
        raise CiscoHandoverReadinessError("evidence_sha256 must contain exactly C06 through C11")

    normalized_evidence: dict[str, str] = {}
    blockers: list[str] = []
    completed: list[str] = []
    for stage in _REQUIRED_STAGES:
        complete = stage_complete[stage]
        if type(complete) is not bool:
            raise CiscoHandoverReadinessError(f"stage completion must be boolean: {stage}")
        digest = str(evidence_sha256[stage] or "").strip().lower()
        if not _SHA256_RE.fullmatch(digest):
            raise CiscoHandoverReadinessError(f"valid evidence SHA-256 required: {stage}")
        normalized_evidence[stage] = digest
        if complete:
            completed.append(stage)
        else:
            blockers.append(f"{stage}_INCOMPLETE")

    if stage_complete["C11"] and physical_device_verified is not True:
        blockers.append("C11_PHYSICAL_DEVICE_NOT_VERIFIED")
    if physical_device_verified is True and stage_complete["C11"] is not True:
        raise CiscoHandoverReadinessError("physical_device_verified cannot be true while C11 is incomplete")

    evidence_bundle = _canonical_sha256({
        "schema_version": "cisco-c12-prerequisite-evidence-bundle/1",
        "evidence_sha256": normalized_evidence,
    })
    ready = not blockers and physical_device_verified is True
    unsigned = {
        "schema_version": "cisco-c12-pre-handover-readiness/1",
        "required_stages": list(_REQUIRED_STAGES),
        "completed_stages": completed,
        "blockers": blockers,
        "evidence_bundle_sha256": evidence_bundle,
        "physical_device_verified": physical_device_verified,
        "ready_for_c12_human_review": ready,
        "c12_complete": False,
        "production_writer_available": False,
        "production_write_authorized": False,
    }
    return CiscoHandoverReadiness(
        required_stages=_REQUIRED_STAGES,
        completed_stages=tuple(completed),
        blockers=tuple(blockers),
        evidence_bundle_sha256=evidence_bundle,
        readiness_sha256=_canonical_sha256(unsigned),
        physical_device_verified=physical_device_verified,
        ready_for_c12_human_review=ready,
    )
