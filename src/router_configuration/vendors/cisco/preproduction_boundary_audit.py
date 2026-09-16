"""Recursive pre-production safety-boundary audit for Cisco artifacts.

The audit walks arbitrary sanitized artifact mappings and rejects any truthy write
surface before convergence. It does not mutate artifacts or authorize releases.
"""

from __future__ import annotations

import hashlib
import json
from typing import Any, Mapping, Sequence

_PROHIBITED_TRUE = frozenset({
    "apply_authorized",
    "write_authorized",
    "production_writer_available",
    "production_write_authorized",
})


class CiscoPreproductionBoundaryAuditError(ValueError):
    """Raised when an artifact bundle opens a prohibited write surface."""


def _canonical_sha256(value: object) -> str:
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False, default=str).encode("utf-8")).hexdigest()


def _scan(value: object, path: str, findings: list[str]) -> None:
    if isinstance(value, Mapping):
        for key, child in value.items():
            name = str(key)
            child_path = f"{path}.{name}"
            if name in _PROHIBITED_TRUE and child is True:
                findings.append(child_path)
            _scan(child, child_path, findings)
    elif isinstance(value, Sequence) and not isinstance(value, (str, bytes, bytearray)):
        for index, child in enumerate(value):
            _scan(child, f"{path}[{index}]", findings)


def audit_preproduction_boundary(artifacts: Mapping[str, Any]) -> dict[str, Any]:
    if not artifacts:
        raise CiscoPreproductionBoundaryAuditError("artifact bundle must not be empty")
    findings: list[str] = []
    _scan(artifacts, "$", findings)
    if findings:
        raise CiscoPreproductionBoundaryAuditError(
            "prohibited write surface opened: " + ", ".join(sorted(findings))
        )

    artifact_digests = {
        str(name): _canonical_sha256(value)
        for name, value in sorted(artifacts.items(), key=lambda item: str(item[0]))
    }
    result = {
        "schema_version": "cisco-preproduction-boundary-audit/1",
        "artifact_count": len(artifact_digests),
        "artifact_sha256": artifact_digests,
        "prohibited_write_surface_count": 0,
        "safe_for_convergence_review": True,
        "production_writer_available": False,
        "production_write_authorized": False,
    }
    result["audit_sha256"] = _canonical_sha256(result)
    return result
