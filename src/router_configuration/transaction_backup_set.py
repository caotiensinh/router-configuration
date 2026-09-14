from __future__ import annotations

import hashlib
import hmac
import json
from dataclasses import dataclass
from typing import Any, Mapping

from .transaction_backup_evidence import validate_transaction_backup_evidence


def _canonical_sha256(value: Any) -> str:
    encoded = json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        default=str,
    ).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


@dataclass(frozen=True)
class TransactionBackupSet:
    payload: Mapping[str, Any]

    def as_dict(self) -> dict[str, Any]:
        return dict(self.payload)


def build_transaction_backup_set(
    *,
    sanitized_export: Mapping[str, Any],
    protected_binary: Mapping[str, Any],
) -> TransactionBackupSet:
    """Bind the two complementary pre-change backup artifacts to one pre-state.

    This is evidence accounting only. It carries no storage URL, credential,
    RouterOS transport, restore command or production write capability.
    """

    validate_transaction_backup_evidence(sanitized_export)
    validate_transaction_backup_evidence(protected_binary)
    if sanitized_export.get("kind") != "sanitized_export":
        raise ValueError("sanitized_export must use kind=sanitized_export")
    if protected_binary.get("kind") != "protected_ephemeral_binary":
        raise ValueError("protected_binary must use kind=protected_ephemeral_binary")

    export_state = str(sanitized_export.get("pre_state_sha256") or "")
    binary_state = str(protected_binary.get("pre_state_sha256") or "")
    if not hmac.compare_digest(export_state, binary_state):
        raise ValueError("backup artifacts are bound to different pre-state digests")

    export_ref = str(sanitized_export.get("artifact_ref") or "")
    binary_ref = str(protected_binary.get("artifact_ref") or "")
    if export_ref == binary_ref:
        raise ValueError("backup artifacts must use distinct references")
    if str(sanitized_export.get("sha256")) == str(protected_binary.get("sha256")):
        raise ValueError("sanitized export and binary backup must have distinct digests")

    payload = {
        "schema_version": "routeros-transaction-backup-set/1",
        "pre_state_sha256": export_state,
        "sanitized_export_evidence_sha256": str(sanitized_export["evidence_sha256"]),
        "protected_binary_evidence_sha256": str(protected_binary["evidence_sha256"]),
        "production_backup_requirements_satisfied": True,
        "repository_contains_binary_backup": False,
        "protected_storage_required": True,
        "transport_present": False,
        "restore_available": False,
        "production_writer_available": False,
        "write_authorized": False,
    }
    payload["backup_set_sha256"] = _canonical_sha256(payload)
    return TransactionBackupSet(payload)
