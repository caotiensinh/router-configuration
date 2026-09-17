from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass
from typing import Iterable


class RawSourceVersionError(ValueError):
    pass


_SHA256 = re.compile(r"^[0-9a-f]{64}$")


@dataclass(frozen=True)
class RawSourceVersionRecord:
    source_id: str
    archive_path: str
    byte_length: int
    sha256: str
    version_ordinal: int
    previous_sha256: str | None
    state: str = "RAW_HASH_VERSION_BOUND"

    def as_dict(self) -> dict[str, object]:
        return {
            "source_id": self.source_id,
            "archive_path": self.archive_path,
            "byte_length": self.byte_length,
            "sha256": self.sha256,
            "version_ordinal": self.version_ordinal,
            "previous_sha256": self.previous_sha256,
            "state": self.state,
        }


def _safe_text(value: object, label: str) -> str:
    text = str(value or "").strip()
    if not text or any(c in text for c in ("\n", "\r", "\x00")):
        raise RawSourceVersionError(f"{label} must be a non-empty safe value")
    return text


def bind_raw_source_version(
    *,
    source_id: str,
    archive_path: str,
    raw_bytes: bytes,
    prior_records: Iterable[RawSourceVersionRecord] = (),
) -> RawSourceVersionRecord:
    sid = _safe_text(source_id, "source_id")
    path = _safe_text(archive_path, "archive_path")
    if not path.startswith("raw/") or path.startswith("/") or ".." in path.split("/"):
        raise RawSourceVersionError("archive_path must reference a safe task 11.1 raw/ entry")
    if not isinstance(raw_bytes, (bytes, bytearray)) or not raw_bytes:
        raise RawSourceVersionError("raw_bytes must be non-empty bytes")

    prior = [record for record in prior_records if record.source_id == sid]
    prior.sort(key=lambda item: item.version_ordinal)
    if prior:
        ordinals = [item.version_ordinal for item in prior]
        if ordinals != list(range(1, len(ordinals) + 1)):
            raise RawSourceVersionError("prior version ordinals must be contiguous and monotonic")
        for index, item in enumerate(prior):
            if not _SHA256.fullmatch(item.sha256):
                raise RawSourceVersionError("prior record contains invalid sha256")
            if index == 0:
                if item.previous_sha256 is not None:
                    raise RawSourceVersionError("first version cannot have previous_sha256")
            elif item.previous_sha256 != prior[index - 1].sha256:
                raise RawSourceVersionError("prior hash chain is broken")

    digest = hashlib.sha256(bytes(raw_bytes)).hexdigest()
    if prior and digest == prior[-1].sha256:
        raise RawSourceVersionError("identical raw content is already represented by latest version")

    ordinal = len(prior) + 1
    previous = prior[-1].sha256 if prior else None
    return RawSourceVersionRecord(
        source_id=sid,
        archive_path=path,
        byte_length=len(raw_bytes),
        sha256=digest,
        version_ordinal=ordinal,
        previous_sha256=previous,
    )
