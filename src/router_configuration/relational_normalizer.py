from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass
from typing import Any, Mapping, Sequence


class RelationalNormalizationError(ValueError):
    pass


_SHA256 = re.compile(r"^[0-9a-f]{64}$")
_SECRET_MARKERS = ("password", "private_key", "preshared", "client_secret", "access_token", "refresh_token", "secret")
_CONFIDENCE = frozenset({"VENDOR_DOCUMENT_VERIFIED", "PROTOCOL_VERIFIED", "VIRTUAL_VERIFIED", "HARDWARE_VERIFIED"})


def _safe_text(value: Any, label: str) -> str:
    text = str(value or "").strip()
    if not text or any(c in text for c in ("\n", "\r", "\x00")):
        raise RelationalNormalizationError(f"{label} must be a non-empty safe value")
    return text


def _reject_sensitive(value: Any, path: str = "record") -> None:
    if isinstance(value, Mapping):
        for key, child in value.items():
            name = str(key).strip().lower()
            if any(marker in name for marker in _SECRET_MARKERS):
                raise RelationalNormalizationError(f"{path} contains forbidden secret field: {key}")
            _reject_sensitive(child, f"{path}.{key}")
    elif isinstance(value, (list, tuple)):
        for index, child in enumerate(value):
            _reject_sensitive(child, f"{path}[{index}]")


def _digest(value: Any) -> str:
    raw = json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False, default=str).encode("utf-8")
    return hashlib.sha256(raw).hexdigest()


@dataclass(frozen=True)
class RelationalDataset:
    payload: Mapping[str, Any]

    def as_dict(self) -> dict[str, Any]:
        return dict(self.payload)


def normalize_relational_data(
    *,
    raw_source_versions: Sequence[Mapping[str, Any]],
    facts: Sequence[Mapping[str, Any]],
) -> RelationalDataset:
    if not raw_source_versions:
        raise RelationalNormalizationError("raw_source_versions must not be empty")
    _reject_sensitive(raw_source_versions, "raw_source_versions")
    _reject_sensitive(facts, "facts")

    sources: dict[str, dict[str, Any]] = {}
    versions: dict[tuple[str, int], dict[str, Any]] = {}
    for record in raw_source_versions:
        if record.get("schema_version") != "omada-raw-source-version/1" or record.get("state") != "RAW_HASH_VERSION_BOUND":
            raise RelationalNormalizationError("raw source version is not a bound Omada raw-source record")
        source_id = _safe_text(record.get("source_id"), "source_id")
        source_url = _safe_text(record.get("source_url"), "source_url")
        ordinal = record.get("version_ordinal")
        if not isinstance(ordinal, int) or isinstance(ordinal, bool) or ordinal < 1:
            raise RelationalNormalizationError("version_ordinal must be a positive integer")
        sha256 = str(record.get("sha256") or "").strip().lower()
        if not _SHA256.fullmatch(sha256):
            raise RelationalNormalizationError("raw source sha256 is invalid")
        if source_id in sources and sources[source_id]["source_url"] != source_url:
            raise RelationalNormalizationError("source_id cannot map to multiple source URLs")
        sources[source_id] = {"source_id": source_id, "source_url": source_url}
        key = (source_id, ordinal)
        if key in versions:
            raise RelationalNormalizationError("duplicate source version key")
        versions[key] = {
            "source_id": source_id,
            "version_ordinal": ordinal,
            "sha256": sha256,
            "archive_path": _safe_text(record.get("archive_path"), "archive_path"),
            "retrieved_at": _safe_text(record.get("retrieved_at"), "retrieved_at"),
        }

    fact_rows: dict[str, dict[str, Any]] = {}
    provenance_rows: list[dict[str, Any]] = []
    for raw in facts:
        fact_id = _safe_text(raw.get("fact_id"), "fact_id")
        if fact_id in fact_rows:
            raise RelationalNormalizationError("duplicate fact_id")
        source_id = _safe_text(raw.get("source_id"), "fact.source_id")
        ordinal = raw.get("source_version_ordinal")
        if (source_id, ordinal) not in versions:
            raise RelationalNormalizationError("fact provenance references a missing source version")
        confidence = _safe_text(raw.get("confidence_class"), "confidence_class").upper()
        if confidence not in _CONFIDENCE:
            raise RelationalNormalizationError("unsupported confidence_class")
        row = {
            "fact_id": fact_id,
            "subject_type": _safe_text(raw.get("subject_type"), "subject_type"),
            "subject_id": _safe_text(raw.get("subject_id"), "subject_id"),
            "predicate": _safe_text(raw.get("predicate"), "predicate"),
            "value": raw.get("value"),
            "confidence_class": confidence,
        }
        if row["value"] is None:
            raise RelationalNormalizationError("fact value must not be null")
        fact_rows[fact_id] = row
        provenance_rows.append(
            {
                "fact_id": fact_id,
                "source_id": source_id,
                "source_version_ordinal": ordinal,
                "evidence_locator": _safe_text(raw.get("evidence_locator"), "evidence_locator"),
            }
        )

    tables: dict[str, Any] = {
        "sources": sorted(sources.values(), key=lambda row: row["source_id"]),
        "source_versions": sorted(versions.values(), key=lambda row: (row["source_id"], row["version_ordinal"])),
        "facts": sorted(fact_rows.values(), key=lambda row: row["fact_id"]),
        "fact_provenance": sorted(provenance_rows, key=lambda row: (row["fact_id"], row["source_id"], row["source_version_ordinal"])),
    }
    payload: dict[str, Any] = {
        "schema_version": "omada-relational-dataset/1",
        "tables": tables,
        "row_counts": {name: len(rows) for name, rows in tables.items()},
        "foreign_keys_validated": True,
        "production_write_authority": False,
    }
    payload["dataset_sha256"] = _digest(payload)
    return RelationalDataset(payload)
