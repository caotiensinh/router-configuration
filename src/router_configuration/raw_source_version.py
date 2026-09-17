from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass
from typing import Any, Mapping

_SHA256 = re.compile(r"^[0-9a-f]{64}$")
_FORBIDDEN = frozenset({
    "password", "credential", "credentials", "token", "access_token", "refresh_token",
    "client_secret", "secret", "shared_secret", "private_key", "preshared_key", "psk",
})


class RawSourceVersionError(ValueError):
    pass


def _safe_text(value: Any, label: str) -> str:
    text = str(value or "").strip()
    if not text or any(c in text for c in ("\n", "\r", "\x00")):
        raise RawSourceVersionError(f"{label} must be a non-empty safe value")
    return text


def _reject_sensitive(value: Any, path: str = "raw_source_version") -> None:
    if isinstance(value, Mapping):
        for key, child in value.items():
            name = str(key).strip().lower()
            if name in _FORBIDDEN or any(marker in name for marker in ("password", "private_key", "client_secret", "access_token", "refresh_token")):
                raise RawSourceVersionError(f"{path} contains forbidden secret field: {key}")
            _reject_sensitive(child, f"{path}.{key}")
    elif isinstance(value, (list, tuple)):
        for index, child in enumerate(value):
            _reject_sensitive(child, f"{path}[{index}]")


def _digest(payload: Mapping[str, Any]) -> str:
    raw = json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
    return hashlib.sha256(raw).hexdigest()


@dataclass(frozen=True)
class RawSourceVersionRecord:
    payload: Mapping[str, Any]

    def as_dict(self) -> dict[str, Any]:
        return dict(self.payload)


def bind_raw_source_version(
    *,
    archive_entry: Mapping[str, Any],
    raw_bytes: bytes,
    version_ordinal: int,
    previous_record: Mapping[str, Any] | None = None,
    source_version_label: str | None = None,
) -> RawSourceVersionRecord:
    if not isinstance(archive_entry, Mapping):
        raise RawSourceVersionError("archive_entry must be a mapping")
    _reject_sensitive(archive_entry, "archive_entry")
    if archive_entry.get("state") != "RAW_ARCHIVED_UNVERIFIED":
        raise RawSourceVersionError("archive_entry must be RAW_ARCHIVED_UNVERIFIED")

    source_id = _safe_text(archive_entry.get("source_id"), "source_id")
    source_url = _safe_text(archive_entry.get("source_url"), "source_url")
    retrieved_at = _safe_text(archive_entry.get("retrieved_at"), "retrieved_at")
    archive_path = _safe_text(archive_entry.get("archive_path"), "archive_path")
    if not isinstance(raw_bytes, (bytes, bytearray)) or not raw_bytes:
        raise RawSourceVersionError("raw_bytes must be non-empty bytes")
    if not isinstance(version_ordinal, int) or isinstance(version_ordinal, bool) or version_ordinal < 1:
        raise RawSourceVersionError("version_ordinal must be a positive integer")

    exact = bytes(raw_bytes)
    sha256 = hashlib.sha256(exact).hexdigest()
    previous_sha256: str | None = None
    supersedes: int | None = None

    if version_ordinal == 1:
        if previous_record is not None:
            raise RawSourceVersionError("first version cannot supersede a previous record")
    else:
        if not isinstance(previous_record, Mapping):
            raise RawSourceVersionError("version after 1 requires previous_record")
        _reject_sensitive(previous_record, "previous_record")
        if str(previous_record.get("source_id") or "").strip() != source_id:
            raise RawSourceVersionError("previous_record source_id mismatch")
        previous_ordinal = previous_record.get("version_ordinal")
        if previous_ordinal != version_ordinal - 1:
            raise RawSourceVersionError("version_ordinal must be monotonic and contiguous")
        previous_sha256 = str(previous_record.get("sha256") or "").strip().lower()
        if not _SHA256.fullmatch(previous_sha256):
            raise RawSourceVersionError("previous_record sha256 is invalid")
        if previous_sha256 == sha256:
            raise RawSourceVersionError("unchanged raw bytes must not create a new version")
        supersedes = previous_ordinal

    payload: dict[str, Any] = {
        "schema_version": "omada-raw-source-version/1",
        "source_id": source_id,
        "source_url": source_url,
        "retrieved_at": retrieved_at,
        "archive_path": archive_path,
        "byte_length": len(exact),
        "sha256": sha256,
        "version_ordinal": version_ordinal,
        "previous_sha256": previous_sha256,
        "supersedes_version_ordinal": supersedes,
        "state": "RAW_HASH_VERSION_BOUND",
        "hash_algorithm": "sha256",
        "hash_input": "EXACT_RAW_BYTES",
        "normalization_applied": False,
        "production_write_authority": False,
    }
    if source_version_label is not None:
        payload["source_version_label"] = _safe_text(source_version_label, "source_version_label")
    payload["record_sha256"] = _digest(payload)
    return RawSourceVersionRecord(payload)
