from __future__ import annotations

from dataclasses import dataclass
from enum import Enum


class MikroTikBackupKind(str, Enum):
    SANITIZED_EXPORT = "sanitized_export"
    BINARY_SYSTEM_BACKUP = "binary_system_backup"


@dataclass(frozen=True)
class MikroTikBackupOperation:
    kind: MikroTikBackupKind
    phase: str
    routeros_command_template: str
    sensitive: bool
    requires_secret_reference: bool
    notes: tuple[str, ...]


def backup_operations(*, phase: str) -> tuple[MikroTikBackupOperation, ...]:
    clean_phase = phase.strip().lower()
    if clean_phase not in {"pre_change", "post_change"}:
        raise ValueError("backup phase must be pre_change or post_change")
    return (
        MikroTikBackupOperation(
            kind=MikroTikBackupKind.SANITIZED_EXPORT,
            phase=clean_phase,
            routeros_command_template="/export terse file={artifact_name}",
            sensitive=False,
            requires_secret_reference=False,
            notes=(
                "Human-readable as-built/change evidence.",
                "Does not contain every secret, certificate, SSH key, or auxiliary database.",
            ),
        ),
        MikroTikBackupOperation(
            kind=MikroTikBackupKind.BINARY_SYSTEM_BACKUP,
            phase=clean_phase,
            routeros_command_template="/system/backup/save name={artifact_name} password={resolved_backup_password}",
            sensitive=True,
            requires_secret_reference=True,
            notes=(
                "Contains sensitive device configuration and must be encrypted and access-controlled.",
                "Record RouterOS version and restore compatibility metadata with the artifact.",
            ),
        ),
    )
