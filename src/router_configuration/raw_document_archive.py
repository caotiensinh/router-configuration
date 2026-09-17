from __future__ import annotations

import os
import re
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Iterable
from urllib.parse import urlparse

_SOURCE_ID = re.compile(r"^[A-Za-z0-9._-]+$")


class RawDocumentArchiveError(ValueError):
    pass


@dataclass(frozen=True)
class RawDocumentArchiveEntry:
    source_id: str
    source_url: str
    retrieved_at: str
    media_type: str
    archive_path: str
    authority_scope: str
    state: str = "RAW_ARCHIVED_UNVERIFIED"

    def as_dict(self) -> dict[str, str]:
        return {
            "source_id": self.source_id,
            "source_url": self.source_url,
            "retrieved_at": self.retrieved_at,
            "media_type": self.media_type,
            "archive_path": self.archive_path,
            "authority_scope": self.authority_scope,
            "state": self.state,
        }


def _safe_text(value: str, label: str) -> str:
    text = str(value or "").strip()
    if not text or any(c in text for c in ("\n", "\r", "\x00")):
        raise RawDocumentArchiveError(f"{label} must be a non-empty safe value")
    return text


def _validate_timestamp(value: str) -> str:
    text = _safe_text(value, "retrieved_at")
    try:
        datetime.fromisoformat(text.replace("Z", "+00:00"))
    except ValueError as exc:
        raise RawDocumentArchiveError("retrieved_at must be ISO-8601") from exc
    return text


def _validate_url(value: str) -> str:
    text = _safe_text(value, "source_url")
    parsed = urlparse(text)
    if parsed.scheme not in {"https", "http"} or not parsed.netloc:
        raise RawDocumentArchiveError("source_url must be an absolute HTTP(S) URL")
    return text


def archive_raw_document(
    *,
    root: Path,
    source_id: str,
    source_url: str,
    retrieved_at: str,
    media_type: str,
    authority_scope: str,
    raw_bytes: bytes,
    existing_source_ids: Iterable[str] = (),
) -> RawDocumentArchiveEntry:
    """Persist raw bytes immutably without hashing or normalization.

    Hash/version work belongs to task 11.2 and normalized derivatives belong to 11.3.
    """
    sid = _safe_text(source_id, "source_id")
    if not _SOURCE_ID.fullmatch(sid) or sid in {".", ".."}:
        raise RawDocumentArchiveError("source_id contains unsafe path characters")
    if sid in {str(item).strip() for item in existing_source_ids}:
        raise RawDocumentArchiveError("source_id is already archived")
    if not isinstance(raw_bytes, (bytes, bytearray)) or not raw_bytes:
        raise RawDocumentArchiveError("raw_bytes must be non-empty bytes")

    url = _validate_url(source_url)
    timestamp = _validate_timestamp(retrieved_at)
    mtype = _safe_text(media_type, "media_type")
    scope = _safe_text(authority_scope, "authority_scope")

    root = Path(root)
    raw_dir = root / "raw"
    raw_dir.mkdir(parents=True, exist_ok=True)
    target = raw_dir / f"{sid}.raw"
    resolved_root = root.resolve()
    resolved_target = target.resolve()
    if resolved_target.parent != (resolved_root / "raw").resolve():
        raise RawDocumentArchiveError("archive target escapes raw archive directory")

    try:
        fd = os.open(resolved_target, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    except FileExistsError as exc:
        raise RawDocumentArchiveError("archive target already exists") from exc
    try:
        with os.fdopen(fd, "wb") as handle:
            handle.write(bytes(raw_bytes))
            handle.flush()
            os.fsync(handle.fileno())
    except Exception:
        try:
            resolved_target.unlink(missing_ok=True)
        finally:
            raise

    relative = resolved_target.relative_to(resolved_root).as_posix()
    return RawDocumentArchiveEntry(
        source_id=sid,
        source_url=url,
        retrieved_at=timestamp,
        media_type=mtype,
        archive_path=relative,
        authority_scope=scope,
    )
