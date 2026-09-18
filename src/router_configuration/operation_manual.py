from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass
from typing import Mapping, Sequence


class OperationManualError(ValueError):
    pass


_SHA1 = re.compile(r"^[0-9a-f]{40}$")
_SECRET_MARKERS = ("password", "private_key", "preshared", "client_secret", "access_token", "refresh_token", "secret")


def _safe(value: object, label: str) -> str:
    text = str(value or "").strip()
    if not text:
        raise OperationManualError(f"{label} must not be empty")
    return text


def _reject_sensitive(value: object, path: str = "manual") -> None:
    if isinstance(value, Mapping):
        for key, child in value.items():
            name = str(key).strip().lower()
            if any(marker in name for marker in _SECRET_MARKERS):
                raise OperationManualError(f"{path} contains forbidden secret field: {key}")
            _reject_sensitive(child, f"{path}.{key}")
    elif isinstance(value, (list, tuple)):
        for index, child in enumerate(value):
            _reject_sensitive(child, f"{path}[{index}]")


def _steps(values: Sequence[str], label: str) -> list[str]:
    if not values:
        raise OperationManualError(f"{label} must not be empty")
    return [_safe(item, label) for item in values]


@dataclass(frozen=True)
class OperationManual:
    payload: Mapping[str, object]

    def as_dict(self) -> dict[str, object]:
        return dict(self.payload)


def build_operation_manual(
    *,
    source_main_sha: str,
    system_id: str,
    audience: str,
    prerequisites: Sequence[str],
    startup_steps: Sequence[str],
    health_checks: Sequence[str],
    normal_operations: Sequence[str],
    shutdown_steps: Sequence[str],
    escalation_steps: Sequence[str],
    evidence_refs: Sequence[str],
    known_restrictions: Sequence[str],
    extra: Mapping[str, object] | None = None,
) -> OperationManual:
    sha = str(source_main_sha or "").strip().lower()
    if not _SHA1.fullmatch(sha):
        raise OperationManualError("source_main_sha must be lowercase SHA-1")
    if extra is not None:
        _reject_sensitive(extra)
    refs = sorted({_safe(item, "evidence_ref") for item in evidence_refs})
    if not refs:
        raise OperationManualError("evidence_refs must not be empty")
    payload: dict[str, object] = {
        "schema_version": "operation-manual/1",
        "source_main_sha": sha,
        "system_id": _safe(system_id, "system_id"),
        "audience": _safe(audience, "audience"),
        "prerequisites": _steps(prerequisites, "prerequisites"),
        "startup_steps": _steps(startup_steps, "startup_steps"),
        "health_checks": _steps(health_checks, "health_checks"),
        "normal_operations": _steps(normal_operations, "normal_operations"),
        "shutdown_steps": _steps(shutdown_steps, "shutdown_steps"),
        "escalation_steps": _steps(escalation_steps, "escalation_steps"),
        "evidence_refs": refs,
        "known_restrictions": sorted({_safe(item, "known_restriction") for item in known_restrictions}),
        "instructions_are_non_executable": True,
        "production_write_authority": False,
    }
    raw = json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
    payload["manual_sha256"] = hashlib.sha256(raw).hexdigest()
    return OperationManual(payload)
