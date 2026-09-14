from __future__ import annotations

import json
import re
from dataclasses import dataclass
from importlib.resources import files
from pathlib import Path
from typing import Any, Iterable, Mapping


_TOKEN = re.compile(r"[A-Za-z0-9_./+-]+")


@dataclass(frozen=True)
class MikroTikKnowledgeRecord:
    id: str
    topic: str
    title: str
    summary: str
    source_url: str
    routeros_paths: tuple[str, ...]
    keywords: tuple[str, ...]
    safety_rules: tuple[str, ...]

    def as_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "topic": self.topic,
            "title": self.title,
            "summary": self.summary,
            "source_url": self.source_url,
            "routeros_paths": list(self.routeros_paths),
            "keywords": list(self.keywords),
            "safety_rules": list(self.safety_rules),
        }


@dataclass(frozen=True)
class MikroTikKnowledgeHit:
    score: int
    record: MikroTikKnowledgeRecord

    def as_dict(self) -> dict[str, Any]:
        return {"score": self.score, "record": self.record.as_dict()}


class MikroTikOfflineKnowledge:
    """Local-first MikroTik knowledge retrieval.

    Runtime lookup never performs network I/O. A release can ship only the curated
    seed, or add a synchronized full manual snapshot built by tools/mikrotik/
    sync_offline_knowledge.py. AI providers consume retrieved records; they are
    not allowed to replace the deterministic RouterOS policy/validation layer.
    """

    def __init__(self, records: Iterable[MikroTikKnowledgeRecord]) -> None:
        self._records = tuple(records)
        if not self._records:
            raise ValueError("MikroTik offline knowledge requires at least one record")

    @classmethod
    def bundled(cls) -> "MikroTikOfflineKnowledge":
        resource = files("router_configuration.vendors.mikrotik").joinpath(
            "data/knowledge_seed.json"
        )
        payload = json.loads(resource.read_text(encoding="utf-8"))
        return cls.from_mapping(payload)

    @classmethod
    def from_path(cls, path: str | Path) -> "MikroTikOfflineKnowledge":
        payload = json.loads(Path(path).read_text(encoding="utf-8"))
        return cls.from_mapping(payload)

    @classmethod
    def from_mapping(cls, payload: Mapping[str, Any]) -> "MikroTikOfflineKnowledge":
        if payload.get("schema_version") != "mikrotik-offline-knowledge/1":
            raise ValueError("unsupported MikroTik offline knowledge schema")
        if payload.get("vendor") != "mikrotik":
            raise ValueError("offline knowledge vendor must be mikrotik")
        raw_records = payload.get("records")
        if not isinstance(raw_records, list):
            raise ValueError("offline knowledge records must be a list")
        records: list[MikroTikKnowledgeRecord] = []
        for index, item in enumerate(raw_records):
            if not isinstance(item, Mapping):
                raise ValueError(f"offline knowledge record {index} must be an object")
            records.append(
                MikroTikKnowledgeRecord(
                    id=str(item.get("id") or "").strip(),
                    topic=str(item.get("topic") or "").strip(),
                    title=str(item.get("title") or "").strip(),
                    summary=str(item.get("summary") or "").strip(),
                    source_url=str(item.get("source_url") or "").strip(),
                    routeros_paths=tuple(str(v) for v in item.get("routeros_paths", [])),
                    keywords=tuple(str(v) for v in item.get("keywords", [])),
                    safety_rules=tuple(str(v) for v in item.get("safety_rules", [])),
                )
            )
        if any(not item.id or not item.title or not item.summary for item in records):
            raise ValueError("offline knowledge records require id/title/summary")
        return cls(records)

    @property
    def records(self) -> tuple[MikroTikKnowledgeRecord, ...]:
        return self._records

    @staticmethod
    def _tokens(value: str) -> set[str]:
        return {token.lower() for token in _TOKEN.findall(value)}

    def search(self, query: str, *, limit: int = 6) -> tuple[MikroTikKnowledgeHit, ...]:
        if limit < 1:
            raise ValueError("limit must be positive")
        wanted = self._tokens(query)
        if not wanted:
            return ()
        hits: list[MikroTikKnowledgeHit] = []
        for record in self._records:
            title = self._tokens(record.title)
            keywords = self._tokens(" ".join(record.keywords))
            paths = self._tokens(" ".join(record.routeros_paths))
            summary = self._tokens(record.summary)
            safety = self._tokens(" ".join(record.safety_rules))
            score = (
                8 * len(wanted & title)
                + 6 * len(wanted & keywords)
                + 5 * len(wanted & paths)
                + 2 * len(wanted & safety)
                + len(wanted & summary)
            )
            if score:
                hits.append(MikroTikKnowledgeHit(score=score, record=record))
        hits.sort(key=lambda item: (-item.score, item.record.id))
        return tuple(hits[:limit])

    def context(self, query: str, *, limit: int = 6) -> tuple[dict[str, Any], ...]:
        return tuple(hit.as_dict() for hit in self.search(query, limit=limit))
