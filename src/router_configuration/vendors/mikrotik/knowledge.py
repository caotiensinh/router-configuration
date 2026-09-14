from __future__ import annotations

import json
import re
from dataclasses import dataclass
from importlib.resources import files
from pathlib import Path
from typing import Any, Iterable, Mapping


_TOKEN = re.compile(r"[A-Za-z0-9_./+-]+")
_BUNDLED_KNOWLEDGE_FILES = ("knowledge_seed.json", "knowledge_script.json")


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
    """Local-first MikroTik knowledge retrieval with additive bundled fragments.

    Runtime lookup never performs network I/O. The bundled structured knowledge
    is deliberately split into small reviewed fragments so new official RouterOS
    rules can be added without rewriting the entire seed. A synchronized full
    manual snapshot can still be stored beside the structured bundle for deeper
    local retrieval.
    """

    def __init__(self, records: Iterable[MikroTikKnowledgeRecord]) -> None:
        self._records = tuple(records)
        if not self._records:
            raise ValueError("MikroTik offline knowledge requires at least one record")
        ids = [item.id for item in self._records]
        if len(ids) != len(set(ids)):
            raise ValueError("MikroTik offline knowledge record IDs must be unique")
        self._by_id = {item.id: item for item in self._records}

    @classmethod
    def bundled(cls) -> "MikroTikOfflineKnowledge":
        root = files("router_configuration.vendors.mikrotik").joinpath("data")
        records: list[MikroTikKnowledgeRecord] = []
        for name in _BUNDLED_KNOWLEDGE_FILES:
            resource = root.joinpath(name)
            payload = json.loads(resource.read_text(encoding="utf-8"))
            records.extend(cls._records_from_mapping(payload))
        return cls(records)

    @classmethod
    def from_path(cls, path: str | Path) -> "MikroTikOfflineKnowledge":
        payload = json.loads(Path(path).read_text(encoding="utf-8"))
        return cls.from_mapping(payload)

    @classmethod
    def from_mapping(cls, payload: Mapping[str, Any]) -> "MikroTikOfflineKnowledge":
        return cls(cls._records_from_mapping(payload))

    @staticmethod
    def _records_from_mapping(payload: Mapping[str, Any]) -> list[MikroTikKnowledgeRecord]:
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
            record = MikroTikKnowledgeRecord(
                id=str(item.get("id") or "").strip(),
                topic=str(item.get("topic") or "").strip(),
                title=str(item.get("title") or "").strip(),
                summary=str(item.get("summary") or "").strip(),
                source_url=str(item.get("source_url") or "").strip(),
                routeros_paths=tuple(str(v) for v in item.get("routeros_paths", [])),
                keywords=tuple(str(v) for v in item.get("keywords", [])),
                safety_rules=tuple(str(v) for v in item.get("safety_rules", [])),
            )
            if not record.id or not record.title or not record.summary or not record.source_url:
                raise ValueError("offline knowledge records require id/title/summary/source_url")
            records.append(record)
        return records

    @property
    def records(self) -> tuple[MikroTikKnowledgeRecord, ...]:
        return self._records

    def get(self, record_id: str) -> MikroTikKnowledgeRecord:
        try:
            return self._by_id[record_id]
        except KeyError as exc:
            raise KeyError(f"unknown MikroTik knowledge record: {record_id}") from exc

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
