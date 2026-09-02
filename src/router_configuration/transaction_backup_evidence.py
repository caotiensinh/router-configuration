from __future__ import annotations

import hashlib
import hmac
import json
import re
from dataclasses import dataclass
from typing import Any, Mapping


class TransactionBackupEvidenceError(ValueError):
    pass


_SHA256 = re.compile(r"^[0-9a-f]{64}$")
_ALLOWED_KINDS = {"sanitized_export", "protected_ephemeral_binary"}
_EXPECTED_FIELDS = {
    "schema_version",
    "kind",
    "ok",
    "readable",
    "artifact_ref",
    "sha256",
    "pre_state_sha256",
    "repository_safe",
    "binary_payload_present",
    "protected_storage_required",
    "production_writer_available",
    "write_authorized",
    "evidence_sha256",
}


def _canonical_sha256(value: Any) -> str:
    encoded = json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        default=str,
    ).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def _digest(value: Any, label: str) -> str:
    text = str(value or "").strip().lower()
    if not _SHA256.fullmatch(text):
        raise TransactionBackupEvidenceError(f"{label} must be a lowercase SHA-256 digest")
    return text


def _reference(value: Any, label: str) -> str:
    text = str(value or "").strip()
    if not text:
        raise TransactionBackupEvidenceError(f"{label} must not be empty")
    if any(character in text for character in ("\n", "\r", "\x00")):
        raise TransactionBackupEvidenceError(f"{label} contains unsupported control characters")
    return text


def _validate_reference(kind: str, artifact_ref: str) -> None:
    lowered = artifact_ref.lower()
    if kind == "sanitized_export":
        if not artifact_ref.startswith("artifact://"):
            raise TransactionBackupEvidenceError(
                "sanitized export references must use artifact://"
            )
        if ".backup" in lowered:
            raise TransactionBackupEvidenceError(
                "RouterOS binary .backup must not be stored in repository-safe evidence"
            )
        return
    if not artifact_ref.startswith("protected-ref://"):
        raise TransactionBackupEvidenceError(
            "protected binary backup references must use protected-ref://"
        )
    if any(marker in lowered for marker in ("file://", "http://", "https://", "s3://")):
        raise TransactionBackupEvidenceError(
            "protected binary backup reference must be opaque and non-routable"
        )


@dataclass(frozen=True)
class TransactionBackupEvidence:
    payload: Mapping[str, Any]

    def as_dict(self) -> dict[str, Any]:
        return dict(self.payload)


def build_transaction_backup_evidence(
    *,
    kind: str,
    artifact_ref: str,
    sha256: str,
    pre_state_sha256: str,
) -> TransactionBackupEvidence:
    """Create repository-safe pre-change backup evidence.

    Sanitized exports may be retained as normal CI/Git artifacts. RouterOS binary
    backups are represented only by an opaque protected-storage reference and a
    digest; binary bytes, storage URLs and credentials never enter this payload.
    """

    normalized_kind = str(kind or "").strip()
    if normalized_kind not in _ALLOWED_KINDS:
        raise TransactionBackupEvidenceError("unsupported transaction backup evidence kind")
    normalized_ref = _reference(artifact_ref, "artifact_ref")
    _validate_reference(normalized_kind, normalized_ref)
    artifact_sha = _digest(sha256, "sha256")
    state_sha = _digest(pre_state_sha256, "pre_state_sha256")

    payload = {
        "schema_version": "routeros-transaction-backup-evidence/1",
        "kind": normalized_kind,
        "ok": True,
        "readable": True,
        "artifact_ref": normalized_ref,
        "sha256": artifact_sha,
        "pre_state_sha256": state_sha,
        "repository_safe": True,
        "binary_payload_present": False,
        "protected_storage_required": normalized_kind == "protected_ephemeral_binary",
        "production_writer_available": False,
        "write_authorized": False,
    }
    payload["evidence_sha256"] = _canonical_sha256(payload)
    return TransactionBackupEvidence(payload)


def validate_transaction_backup_evidence(
    evidence: Mapping[str, Any],
    *,
    expected_pre_state_sha256: str | None = None,
) -> None:
    if evidence.get("schema_version") != "routeros-transaction-backup-evidence/1":
        raise TransactionBackupEvidenceError("unsupported transaction backup evidence schema")
    unexpected = sorted(str(key) for key in evidence if str(key) not in _EXPECTED_FIELDS)
    missing = sorted(field for field in _EXPECTED_FIELDS if field not in evidence)
    if unexpected:
        raise TransactionBackupEvidenceError(
            "transaction backup evidence contains unexpected fields: " + ", ".join(unexpected)
        )
    if missing:
        raise TransactionBackupEvidenceError(
            "transaction backup evidence is missing fields: " + ", ".join(missing)
        )

    kind = str(evidence.get("kind") or "")
    if kind not in _ALLOWED_KINDS:
        raise TransactionBackupEvidenceError("unsupported transaction backup evidence kind")
    if evidence.get("ok") is not True or evidence.get("readable") is not True:
        raise TransactionBackupEvidenceError("backup evidence must be successful and readable")
    if evidence.get("repository_safe") is not True:
        raise TransactionBackupEvidenceError("backup evidence must be repository_safe=true")
    if evidence.get("binary_payload_present") is not False:
        raise TransactionBackupEvidenceError("binary backup payload must not be embedded")
    if evidence.get("protected_storage_required") is not (
        kind == "protected_ephemeral_binary"
    ):
        raise TransactionBackupEvidenceError("protected storage policy does not match backup kind")
    if evidence.get("production_writer_available") is not False:
        raise TransactionBackupEvidenceError("backup evidence must not expose a production writer")
    if evidence.get("write_authorized") is not False:
        raise TransactionBackupEvidenceError("backup evidence must keep write_authorized=false")

    artifact_ref = _reference(evidence.get("artifact_ref"), "artifact_ref")
    _validate_reference(kind, artifact_ref)
    _digest(evidence.get("sha256"), "sha256")
    state_sha = _digest(evidence.get("pre_state_sha256"), "pre_state_sha256")
    if expected_pre_state_sha256 is not None:
        expected = _digest(expected_pre_state_sha256, "expected_pre_state_sha256")
        if not hmac.compare_digest(state_sha, expected):
            raise TransactionBackupEvidenceError(
                "backup evidence is bound to a different pre-state digest"
            )

    supplied = _digest(evidence.get("evidence_sha256"), "evidence_sha256")
    unsigned = dict(evidence)
    unsigned.pop("evidence_sha256", None)
    if not hmac.compare_digest(supplied, _canonical_sha256(unsigned)):
        raise TransactionBackupEvidenceError("transaction backup evidence digest mismatch")
