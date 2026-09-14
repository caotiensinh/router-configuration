from __future__ import annotations

from dataclasses import dataclass
import hashlib
from typing import Mapping


@dataclass(frozen=True)
class KnowledgeSnapshot:
    source_url: str
    retrieved_at: str
    sha256: str
    size_bytes: int
    stage: str = "staging"

    def as_dict(self) -> dict[str, object]:
        return {
            "source_url": self.source_url,
            "retrieved_at": self.retrieved_at,
            "sha256": self.sha256,
            "size_bytes": self.size_bytes,
            "stage": self.stage,
        }


def stage_document(*, source_url: str, retrieved_at: str, content: bytes) -> KnowledgeSnapshot:
    if not source_url.startswith("https://"):
        raise ValueError("knowledge source must use https")
    if not retrieved_at.strip():
        raise ValueError("retrieved_at is required")
    if not content:
        raise ValueError("empty knowledge document cannot be staged")
    return KnowledgeSnapshot(
        source_url=source_url,
        retrieved_at=retrieved_at,
        sha256=hashlib.sha256(content).hexdigest(),
        size_bytes=len(content),
    )


def snapshot_changed(previous: KnowledgeSnapshot, current: KnowledgeSnapshot) -> bool:
    if previous.source_url != current.source_url:
        raise ValueError("cannot diff snapshots from different sources")
    return previous.sha256 != current.sha256


def promotion_ready(checks: Mapping[str, bool]) -> bool:
    required = ("parsed", "diff_reviewed", "validated", "tested", "reviewed")
    return all(checks.get(name) is True for name in required)
