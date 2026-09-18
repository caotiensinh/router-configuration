from __future__ import annotations

import hashlib
import json
import math
import re
from dataclasses import dataclass
from typing import Iterable, Sequence


class SemanticIndexError(ValueError):
    pass


_SHA256 = re.compile(r"^[0-9a-f]{64}$")


def _safe(value: object, label: str) -> str:
    text = str(value or "").strip()
    if not text or any(ch in text for ch in ("\n", "\r", "\x00")):
        raise SemanticIndexError(f"{label} must be a non-empty single-line value")
    return text


def _vector(values: Sequence[float], *, expected_dimension: int | None = None) -> tuple[float, ...]:
    if not values:
        raise SemanticIndexError("embedding vector must not be empty")
    vector = tuple(float(value) for value in values)
    if expected_dimension is not None and len(vector) != expected_dimension:
        raise SemanticIndexError("embedding dimension mismatch")
    if not all(math.isfinite(value) for value in vector):
        raise SemanticIndexError("embedding values must be finite")
    norm = math.sqrt(sum(value * value for value in vector))
    if norm == 0:
        raise SemanticIndexError("zero-norm embedding is invalid")
    return vector


@dataclass(frozen=True)
class SemanticDocument:
    document_id: str
    title: str
    source_sha256: str
    embedding_model: str
    vector_provenance_ref: str
    vector: tuple[float, ...]


class SemanticRetrievalIndex:
    def __init__(self, *, embedding_model: str, dimension: int) -> None:
        self.embedding_model = _safe(embedding_model, "embedding_model")
        if not isinstance(dimension, int) or isinstance(dimension, bool) or dimension < 1:
            raise SemanticIndexError("dimension must be a positive integer")
        self.dimension = dimension
        self._documents: dict[str, SemanticDocument] = {}

    def add_document(
        self,
        *,
        document_id: str,
        title: str,
        source_sha256: str,
        vector: Sequence[float],
        vector_provenance_ref: str,
    ) -> None:
        identifier = _safe(document_id, "document_id")
        if identifier in self._documents:
            raise SemanticIndexError("duplicate document_id")
        digest = str(source_sha256 or "").strip().lower()
        if not _SHA256.fullmatch(digest):
            raise SemanticIndexError("source_sha256 must be lowercase SHA-256")
        self._documents[identifier] = SemanticDocument(
            document_id=identifier,
            title=_safe(title, "title"),
            source_sha256=digest,
            embedding_model=self.embedding_model,
            vector_provenance_ref=_safe(vector_provenance_ref, "vector_provenance_ref"),
            vector=_vector(vector, expected_dimension=self.dimension),
        )

    def search(self, query_vector: Sequence[float], *, limit: int = 20, min_score: float = -1.0) -> list[dict[str, object]]:
        if not isinstance(limit, int) or isinstance(limit, bool) or limit < 1:
            raise SemanticIndexError("limit must be a positive integer")
        query = _vector(query_vector, expected_dimension=self.dimension)
        if not math.isfinite(float(min_score)) or not -1.0 <= float(min_score) <= 1.0:
            raise SemanticIndexError("min_score must be between -1 and 1")
        query_norm = math.sqrt(sum(value * value for value in query))
        rows: list[dict[str, object]] = []
        for document in self._documents.values():
            doc_norm = math.sqrt(sum(value * value for value in document.vector))
            dot = sum(a * b for a, b in zip(query, document.vector))
            score = dot / (query_norm * doc_norm)
            if score >= float(min_score):
                rows.append({
                    "document_id": document.document_id,
                    "title": document.title,
                    "source_sha256": document.source_sha256,
                    "score": round(score, 12),
                    "vector_provenance_ref": document.vector_provenance_ref,
                })
        rows.sort(key=lambda row: (-float(row["score"]), str(row["document_id"])))
        return rows[:limit]

    def manifest(self) -> dict[str, object]:
        payload: dict[str, object] = {
            "schema_version": "omada-semantic-retrieval-index/1",
            "embedding_model": self.embedding_model,
            "dimension": self.dimension,
            "document_count": len(self._documents),
            "documents": [
                {
                    "document_id": doc.document_id,
                    "title": doc.title,
                    "source_sha256": doc.source_sha256,
                    "vector_provenance_ref": doc.vector_provenance_ref,
                }
                for doc in sorted(self._documents.values(), key=lambda item: item.document_id)
            ],
            "embedding_generation_in_scope": False,
            "production_write_authority": False,
        }
        raw = json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
        payload["index_sha256"] = hashlib.sha256(raw).hexdigest()
        return payload
