from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass
from typing import Any, Mapping, Sequence


class SecurityComplianceReportError(ValueError):
    pass


_SHA1 = re.compile(r"^[0-9a-f]{40}$")
_STATUSES = frozenset({"VERIFIED", "PARTIAL", "FAILED", "NOT_APPLICABLE", "UNKNOWN"})
_SECRET_MARKERS = ("password", "private_key", "preshared", "client_secret", "access_token", "refresh_token", "secret")


def _safe_text(value: Any, label: str) -> str:
    text = str(value or "").strip()
    if not text or any(c in text for c in ("\n", "\r", "\x00")):
        raise SecurityComplianceReportError(f"{label} must be a non-empty safe value")
    return text


def _reject_sensitive(value: Any, path: str = "report") -> None:
    if isinstance(value, Mapping):
        for key, child in value.items():
            name = str(key).strip().lower()
            if any(marker in name for marker in _SECRET_MARKERS):
                raise SecurityComplianceReportError(f"{path} contains forbidden secret field: {key}")
            _reject_sensitive(child, f"{path}.{key}")
    elif isinstance(value, (list, tuple)):
        for index, child in enumerate(value):
            _reject_sensitive(child, f"{path}[{index}]")


def _digest(value: Any) -> str:
    raw = json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False, default=str).encode("utf-8")
    return hashlib.sha256(raw).hexdigest()


@dataclass(frozen=True)
class TechnicalSecurityComplianceReport:
    payload: Mapping[str, Any]

    def as_dict(self) -> dict[str, Any]:
        return dict(self.payload)


def build_technical_security_compliance_report(
    *,
    source_main_sha: str,
    environment_id: str,
    generated_at: str,
    findings: Sequence[Mapping[str, Any]],
    known_restrictions: Sequence[str],
) -> TechnicalSecurityComplianceReport:
    sha = str(source_main_sha or "").strip().lower()
    if not _SHA1.fullmatch(sha):
        raise SecurityComplianceReportError("source_main_sha must be a lowercase SHA-1")
    environment = _safe_text(environment_id, "environment_id")
    timestamp = _safe_text(generated_at, "generated_at")
    _reject_sensitive(findings, "findings")
    _reject_sensitive(known_restrictions, "known_restrictions")
    if not findings:
        raise SecurityComplianceReportError("findings must not be empty")

    normalized: list[dict[str, Any]] = []
    for raw in findings:
        framework = _safe_text(raw.get("framework"), "framework")
        control_id = _safe_text(raw.get("control_id"), "control_id")
        requirement = _safe_text(raw.get("requirement"), "requirement")
        status = _safe_text(raw.get("status"), "status").upper()
        if status not in _STATUSES:
            raise SecurityComplianceReportError("unsupported finding status")
        implementation = _safe_text(raw.get("vendor_implementation"), "vendor_implementation")
        evidence = sorted({_safe_text(item, "evidence_ref") for item in raw.get("evidence_refs", ())})
        rationale = str(raw.get("rationale") or "").strip()
        if status in {"VERIFIED", "PARTIAL", "FAILED"} and not evidence:
            raise SecurityComplianceReportError(f"{status} finding requires evidence_refs")
        if status == "NOT_APPLICABLE" and not rationale:
            raise SecurityComplianceReportError("NOT_APPLICABLE finding requires rationale")
        normalized.append(
            {
                "framework": framework,
                "control_id": control_id,
                "requirement": requirement,
                "status": status,
                "vendor_implementation": implementation,
                "evidence_refs": evidence,
                "rationale": rationale,
            }
        )

    normalized.sort(key=lambda row: (row["framework"], row["control_id"], row["requirement"]))
    restrictions = sorted({_safe_text(item, "known_restriction") for item in known_restrictions})
    summary = {status: sum(1 for row in normalized if row["status"] == status) for status in sorted(_STATUSES)}
    payload: dict[str, Any] = {
        "schema_version": "technical-security-compliance-report/1",
        "source_main_sha": sha,
        "environment_id": environment,
        "generated_at": timestamp,
        "findings": normalized,
        "summary": summary,
        "known_restrictions": restrictions,
        "report_scope": "TECHNICAL_CONTROL_MAPPING_ONLY",
        "certification_claimed": False,
        "organizational_compliance_claimed": False,
        "production_write_authority": False,
    }
    payload["report_sha256"] = _digest(payload)
    return TechnicalSecurityComplianceReport(payload)
