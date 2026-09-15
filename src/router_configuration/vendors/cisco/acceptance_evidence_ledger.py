"""Deterministic evidence ledger for Cisco acceptance stages C06 through C12.

The ledger records stage artifact digests and lifecycle status only. It does not
accept evidence, infer hardware presence, or authorize writes.
"""

from __future__ import annotations

import hashlib
import json
import re
from typing import Any, Mapping

_SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
_STAGES = ("c06", "c07", "c08", "c09", "c10", "c11", "c12")
_STATUSES = frozenset({"blocked", "candidate", "review_ready", "accepted"})


class CiscoAcceptanceEvidenceLedgerError(ValueError):
    """Raised when an evidence-ledger entry is malformed or unsafe."""


def _canonical_sha256(value: object) -> str:
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")).hexdigest()


def build_acceptance_evidence_ledger(entries: Mapping[str, Mapping[str, Any]]) -> dict[str, Any]:
    if set(entries) != set(_STAGES):
        raise CiscoAcceptanceEvidenceLedgerError("ledger requires exactly C06-C12 entries")

    normalized: dict[str, dict[str, Any]] = {}
    for stage in _STAGES:
        item = entries[stage]
        status = str(item.get("status", "")).strip()
        if status not in _STATUSES:
            raise CiscoAcceptanceEvidenceLedgerError(f"unsupported status for {stage}")
        digest = str(item.get("artifact_sha256", "")).strip().lower()
        if not _SHA256_RE.fullmatch(digest):
            raise CiscoAcceptanceEvidenceLedgerError(f"invalid artifact digest for {stage}")
        if item.get("production_write_authorized") is not False:
            raise CiscoAcceptanceEvidenceLedgerError(f"{stage} carries production write authority")
        normalized[stage] = {
            "status": status,
            "artifact_sha256": digest,
        }

    accepted_prefix: list[str] = []
    for stage in _STAGES:
        if normalized[stage]["status"] != "accepted":
            break
        accepted_prefix.append(stage)

    result = {
        "schema_version": "cisco-acceptance-evidence-ledger/1",
        "entries": normalized,
        "accepted_prefix": accepted_prefix,
        "accepted_stage_count": sum(1 for item in normalized.values() if item["status"] == "accepted"),
        "review_ready_stage_count": sum(1 for item in normalized.values() if item["status"] == "review_ready"),
        "all_stages_accepted": len(accepted_prefix) == len(_STAGES),
        "production_write_authorized": False,
    }
    result["ledger_sha256"] = _canonical_sha256(result)
    return result
