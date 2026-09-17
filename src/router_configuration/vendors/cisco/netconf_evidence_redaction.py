"""Repository-safe redaction for Cisco C03 live NETCONF evidence.

The live probe may hold runtime-only identity strings while connected. This module
creates the artifact-safe form: raw target host/hostname/session identifiers are
removed, stable SHA-256 digests are retained, and the original evidence digest is
bound into a new deterministic record. It never upgrades a candidate probe into
accepted C03 repository evidence by itself.
"""

from __future__ import annotations

import hashlib
import json
import re
from typing import Mapping, Any

_SHA40 = re.compile(r"^[0-9a-f]{40}$")
_SHA256 = re.compile(r"^[0-9a-f]{64}$")
_RUNTIME_ONLY_FIELDS = frozenset({"target_host", "hostname", "session_id"})
_FORBIDDEN_KEY_PARTS = ("password", "secret", "token", "private_key", "private-key", "credential")


class CiscoNetconfRedactionError(ValueError):
    """Raised when C03 evidence cannot be safely persisted."""


def _canonical_sha256(value: object) -> str:
    raw = json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True)
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()


def _text_digest(value: object, field: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise CiscoNetconfRedactionError(f"missing runtime identity field: {field}")
    return hashlib.sha256(value.strip().encode("utf-8")).hexdigest()


def _reject_sensitive_keys(value: object, path: str = "$") -> None:
    if isinstance(value, Mapping):
        for key, child in value.items():
            normalized = str(key).lower()
            if any(marker in normalized for marker in _FORBIDDEN_KEY_PARTS):
                raise CiscoNetconfRedactionError(f"sensitive key rejected at {path}.{key}")
            _reject_sensitive_keys(child, f"{path}.{key}")
    elif isinstance(value, (list, tuple)):
        for index, child in enumerate(value):
            _reject_sensitive_keys(child, f"{path}[{index}]")


def redact_live_netconf_evidence(evidence: Mapping[str, Any]) -> dict[str, Any]:
    """Return a deterministic repository-safe C03 evidence record."""

    if not isinstance(evidence, Mapping):
        raise CiscoNetconfRedactionError("C03 evidence must be an object")
    _reject_sensitive_keys(evidence)
    if evidence.get("schema_version") != "cisco-c03-live-evidence/1":
        raise CiscoNetconfRedactionError("unsupported C03 live-evidence schema")
    source_sha = str(evidence.get("source_sha", "")).strip().lower()
    if not _SHA40.fullmatch(source_sha):
        raise CiscoNetconfRedactionError("C03 source_sha must be a pinned Git SHA")
    original_digest = str(evidence.get("evidence_digest_sha256", "")).strip().lower()
    if not _SHA256.fullmatch(original_digest):
        raise CiscoNetconfRedactionError("C03 evidence digest is missing or invalid")

    unsigned = {key: value for key, value in evidence.items() if key != "evidence_digest_sha256"}
    if _canonical_sha256(unsigned) != original_digest:
        raise CiscoNetconfRedactionError("C03 evidence digest mismatch")

    if evidence.get("stage") != "live_readonly_verified" or evidence.get("c03_complete") is not True:
        raise CiscoNetconfRedactionError("only a successful live-readonly probe can be redacted")
    for key in ("live_target_observed", "hostkey_verified", "required_models_present"):
        if evidence.get(key) is not True:
            raise CiscoNetconfRedactionError(f"C03 success invariant missing: {key}")
    for key in ("write_operations_performed", "production_write_authorized", "physical_device_verified"):
        if evidence.get(key) is not False:
            raise CiscoNetconfRedactionError(f"C03 safety boundary violated: {key}")

    sanitized = dict(evidence)
    sanitized["target_host_digest_sha256"] = _text_digest(evidence.get("target_host"), "target_host")
    sanitized["hostname_digest_sha256"] = _text_digest(evidence.get("hostname"), "hostname")
    for field in _RUNTIME_ONLY_FIELDS:
        sanitized.pop(field, None)
    sanitized.pop("evidence_digest_sha256", None)
    sanitized["runtime_identity_redacted"] = True
    sanitized["source_evidence_digest_sha256"] = original_digest
    sanitized["repository_c03_complete"] = False
    sanitized["repository_evidence_accepted"] = False
    sanitized["schema_version"] = "cisco-c03-repository-evidence/1"
    sanitized["repository_record_sha256"] = _canonical_sha256(sanitized)
    return sanitized
