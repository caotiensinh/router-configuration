"""Fail-closed C12 human-handover manifest builder.

The builder requires accepted prerequisite-stage evidence references before it can
mark a package ready for human handover review. It never completes C12 and never
authorizes production writes.
"""

from __future__ import annotations

import hashlib
import json
import re
from typing import Any, Mapping

_SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
_REF_RE = re.compile(r"^[A-Za-z0-9_.:@/-]{1,128}$")
_REQUIRED_STAGES = ("c06", "c07", "c08", "c09", "c10", "c11")


class CiscoC12HandoverManifestError(ValueError):
    """Raised when a C12 handover package is incomplete or unsafe."""


def _canonical_sha256(value: object) -> str:
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")).hexdigest()


def _sha(value: object, label: str) -> str:
    text = str(value or "").strip().lower()
    if not _SHA256_RE.fullmatch(text):
        raise CiscoC12HandoverManifestError(f"{label} must be lowercase SHA-256")
    return text


def build_c12_handover_manifest(
    stages: Mapping[str, Mapping[str, Any]],
    *,
    handover_id: str,
    owner_ref: str,
) -> dict[str, Any]:
    if set(stages) != set(_REQUIRED_STAGES):
        raise CiscoC12HandoverManifestError("C12 manifest requires exactly C06-C11 stage records")
    hid = str(handover_id).strip()
    owner = str(owner_ref).strip()
    if not _REF_RE.fullmatch(hid) or not _REF_RE.fullmatch(owner):
        raise CiscoC12HandoverManifestError("invalid handover identity")

    evidence: dict[str, str] = {}
    for stage in _REQUIRED_STAGES:
        item = stages[stage]
        if item.get("complete") is not True:
            raise CiscoC12HandoverManifestError(f"{stage.upper()} is not complete")
        if item.get("production_write_authorized") is not False:
            raise CiscoC12HandoverManifestError(f"{stage.upper()} carries production write authority")
        evidence[stage] = _sha(item.get("evidence_sha256"), f"{stage}.evidence_sha256")

    if stages["c11"].get("physical_device_verified") is not True:
        raise CiscoC12HandoverManifestError("C11 physical device verification is required")

    result = {
        "schema_version": "cisco-c12-handover-manifest/1",
        "handover_id": hid,
        "owner_ref": owner,
        "stage_evidence_sha256": evidence,
        "ready_for_c12_human_review": True,
        "c12_complete": False,
        "production_writer_available": False,
        "production_write_authorized": False,
    }
    result["manifest_sha256"] = _canonical_sha256(result)
    return result
