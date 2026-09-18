from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass
from typing import Mapping, Sequence


class MaintenanceManualError(ValueError):
    pass


_SHA1 = re.compile(r"^[0-9a-f]{40}$")
_SECRET_MARKERS = ("password", "private_key", "preshared", "client_secret", "access_token", "refresh_token", "secret")


def _safe(value: object, label: str) -> str:
    text = str(value or "").strip()
    if not text:
        raise MaintenanceManualError(f"{label} must not be empty")
    return text


def _steps(values: Sequence[str], label: str) -> list[str]:
    if not values:
        raise MaintenanceManualError(f"{label} must not be empty")
    return [_safe(item, label) for item in values]


def _reject_sensitive(value: object, path: str = "maintenance_manual") -> None:
    if isinstance(value, Mapping):
        for key, child in value.items():
            name = str(key).strip().lower()
            if any(marker in name for marker in _SECRET_MARKERS):
                raise MaintenanceManualError(f"{path} contains forbidden secret field: {key}")
            _reject_sensitive(child, f"{path}.{key}")
    elif isinstance(value, (list, tuple)):
        for index, child in enumerate(value):
            _reject_sensitive(child, f"{path}[{index}]")


@dataclass(frozen=True)
class MaintenanceManual:
    payload: Mapping[str, object]

    def as_dict(self) -> dict[str, object]:
        return dict(self.payload)


def build_maintenance_manual(
    *,
    source_main_sha: str,
    system_id: str,
    cadence: str,
    pre_maintenance_checks: Sequence[str],
    backup_checks: Sequence[str],
    firmware_lifecycle_checks: Sequence[str],
    routine_tasks: Sequence[str],
    post_maintenance_verification: Sequence[str],
    rollback_readiness_checks: Sequence[str],
    escalation_steps: Sequence[str],
    evidence_refs: Sequence[str],
    known_restrictions: Sequence[str],
    extra: Mapping[str, object] | None = None,
) -> MaintenanceManual:
    sha = str(source_main_sha or "").strip().lower()
    if not _SHA1.fullmatch(sha):
        raise MaintenanceManualError("source_main_sha must be lowercase SHA-1")
    if extra is not None:
        _reject_sensitive(extra)
    refs = sorted({_safe(item, "evidence_ref") for item in evidence_refs})
    if not refs:
        raise MaintenanceManualError("evidence_refs must not be empty")
    payload: dict[str, object] = {
        "schema_version": "maintenance-manual/1",
        "source_main_sha": sha,
        "system_id": _safe(system_id, "system_id"),
        "cadence": _safe(cadence, "cadence"),
        "pre_maintenance_checks": _steps(pre_maintenance_checks, "pre_maintenance_checks"),
        "backup_checks": _steps(backup_checks, "backup_checks"),
        "firmware_lifecycle_checks": _steps(firmware_lifecycle_checks, "firmware_lifecycle_checks"),
        "routine_tasks": _steps(routine_tasks, "routine_tasks"),
        "post_maintenance_verification": _steps(post_maintenance_verification, "post_maintenance_verification"),
        "rollback_readiness_checks": _steps(rollback_readiness_checks, "rollback_readiness_checks"),
        "escalation_steps": _steps(escalation_steps, "escalation_steps"),
        "evidence_refs": refs,
        "known_restrictions": sorted({_safe(item, "known_restriction") for item in known_restrictions}),
        "instructions_are_non_executable": True,
        "production_write_authority": False,
    }
    raw = json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
    payload["manual_sha256"] = hashlib.sha256(raw).hexdigest()
    return MaintenanceManual(payload)
