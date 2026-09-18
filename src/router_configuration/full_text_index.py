from __future__ import annotations

import hashlib
import json
import re
from collections import Counter, defaultdict
from dataclasses import dataclass
from typing import Iterable, Mapping


class FullTextIndexError(ValueError):
    pass


_TOKEN = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:/+-]*")
_SHA256 = re.compile(r"^[0-9a-f]{64}$")
_SECRET_MARKERS = ("password", "private_key", "preshared", "client_secret", "access_token", "refresh_token", "secret")


def _safe(value: object, label: str) -> str:
    text = str(value or "").strip()
    if not text:
        raise FullTextIndexError(f"{label} must not be empty")
    return text


def _reject_sensitive(value: object, path: str = "document") -> None:
    if isinstance(value, Mapping):
        for key, child in value.items():
            name = str(key).lower()
            if any(marker in name for marker in _SECRET_MARKERS):
                raise FullTextIndexError(f"{path} contains forbidden secret field: {key}")
            _reject_sensitive(child, f"{path}.{key}")
    elif isinstance(value, (list, tuple)):
        for index, child in enumerate(value):
            _reject_sensitive(child, f"{path}[{index}]")


def _tokens(text: str) -> list[str]:
    return [match.group(0).lower() for match in _TOKEN.finditer(text)]


@dataclass(frozen=True)
class IndexedDocument:
    document_id: str
    title: str
    body: str
    source_sha256: str

    def tokens(self) -> list[str]:
        return _tokens(self.title + "\n" + self.body)


class FullTextIndex:
    def __init__(self) -> None:
        self._documents: dict[str, IndexedDocument] = {}
        self._postings: dict[str, dict[str, int]] = defaultdict(dict)

    def add_document(self, *, document_id: str, title: str, body: str, source_sha256: str, metadata: Mapping[str, object] | None = None) -> None:
        identifier = _safe(document_id, "document_id")
        if identifier in self._documents:
            raise FullTextIndexError("duplicate document_id")
        digest = str(source_sha256 or "").strip().lower()
        if not _SHA256.fullmatch(digest):
            raise FullTextIndexError("source_sha256 must be lowercase SHA-256")
        if metadata is not None:
            _reject_sensitive(metadata, "metadata")
        document = IndexedDocument(identifier, _safe(title, "title"), _safe(body, "body"), digest)
        counts = Counter(document.tokens())
        if not counts:
            raise FullTextIndexError("document must contain indexable text")
        self._documents[identifier] = document
        for term, count in counts.items():
            self._postings[term][identifier] = count

    def search(self, query: str, *, limit: int = 20) -> list[dict[str, object]]:
        if not isinstance(limit, int) or isinstance(limit, bool) or limit < 1:
            raise FullTextIndexError("limit must be a positive integer")
        terms = _tokens(_safe(query, "query"))
        if not terms:
            raise FullTextIndexError("query has no indexable terms")
        candidate_sets = [set(self._postings.get(term, {})) for term in terms]
        if not candidate_sets or any(not candidates for candidates in candidate_sets):
            return []
        candidates = set.intersection(*candidate_sets)
        rows: list[dict[str, object]] = []
        for document_id in candidates:
            score = sum(self._postings[term][document_id] for term in terms)
            document = self._documents[document_id]
            rows.append({
                "document_id": document_id,
                "title": document.title,
                "source_sha256": document.source_sha256,
                "score": score,
            })
        rows.sort(key=lambda row: (-int(row["score"]), str(row["document_id"])))
        return rows[:limit]

    def manifest(self) -> dict[str, object]:
        payload = {
            "schema_version": "omada-full-text-index/1",
            "document_count": len(self._documents),
            "term_count": len(self._postings),
            "documents": [
                {
                    "document_id": doc.document_id,
                    "source_sha256": doc.source_sha256,
                    "title": doc.title,
                }
                for doc in sorted(self._documents.values(), key=lambda item: item.document_id)
            ],
            "production_write_authority": False,
        }
        raw = json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
        payload["index_sha256"] = hashlib.sha256(raw).hexdigest()
        return payload
