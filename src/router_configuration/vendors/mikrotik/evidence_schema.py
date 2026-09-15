from __future__ import annotations

from dataclasses import dataclass
import hashlib
import json
from typing import Any, Mapping


_SECRET_KEYS = {
    "password",
    "secret",
    "token",
    "private_key",
    "private-key",
    "preshared_key",
    "preshared-key",
    "psk",
}


def _validate_sanitized(value: Any, path: str = "$") -> None:
    if isinstance(value, Mapping):
        for key, nested in value.items():
            normalized = str(key).strip().lower()
            if normalized in _SECRET_KEYS and nested not in (None, "<redacted>", "[redacted]"):
                raise ValueError(f"sensitive value present at {path}.{key}")
            _validate_sanitized(nested, f"{path}.{key}")
    elif isinstance(value, (list, tuple)):
        for index, nested in enumerate(value):
            _validate_sanitized(nested, f"{path}[{index}]")


@dataclass(frozen=True)
class DiagnosticEvidence:
    source_tool: str
    collected_at: str
    payload: Mapping[str, Any]
    sha256: str

    def as_dict(self) -> dict[str, Any]:
        return {
            "schema_version": "mikrotik-diagnostic-evidence/1",
            "source_tool": self.source_tool,
            "collected_at": self.collected_at,
            "payload": dict(self.payload),
            "sha256": self.sha256,
            "write_authorized": False,
        }


def build_diagnostic_evidence(*, source_tool: str, collected_at: str, payload: Mapping[str, Any]) -> DiagnosticEvidence:
    if not source_tool.startswith("mikrotik."):
        raise ValueError("source_tool must be a registered MikroTik tool name")
    if not collected_at.strip():
        raise ValueError("collected_at is required")
    _validate_sanitized(payload)
    canonical = json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
    return DiagnosticEvidence(source_tool, collected_at, dict(payload), hashlib.sha256(canonical).hexdigest())
