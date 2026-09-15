from __future__ import annotations

from dataclasses import dataclass
from importlib.resources import files
import json
from typing import Any, Mapping


@dataclass(frozen=True)
class KnowledgeManifest:
    structured_bundles: tuple[str, ...]
    source_priority: tuple[str, ...]
    runtime_network_required: bool
    ai_authority: str


def validate_knowledge_manifest(payload: Mapping[str, Any]) -> KnowledgeManifest:
    if payload.get("schema_version") != "mikrotik-knowledge-manifest/1":
        raise ValueError("unsupported MikroTik knowledge manifest schema")
    if payload.get("vendor") != "mikrotik":
        raise ValueError("knowledge manifest vendor must be mikrotik")
    if payload.get("runtime_network_required") is not False:
        raise ValueError("MikroTik runtime knowledge must remain offline-first")
    bundles = tuple(str(item) for item in payload.get("structured_bundles", ()))
    if not bundles:
        raise ValueError("knowledge manifest requires structured bundles")
    sources = tuple(str(item) for item in payload.get("source_priority", ()))
    if not sources or any(not url.startswith("https://manual.mikrotik.com/") for url in sources):
        raise ValueError("knowledge manifest primary sources must use current official MikroTik manual")
    ai_authority = str(payload.get("ai_authority") or "")
    if ai_authority != "ordering_and_explanation_only":
        raise ValueError("AI authority must remain advisory")
    return KnowledgeManifest(bundles, sources, False, ai_authority)


def bundled_knowledge_manifest() -> KnowledgeManifest:
    resource = files("router_configuration.vendors.mikrotik").joinpath("data/knowledge_manifest.json")
    return validate_knowledge_manifest(json.loads(resource.read_text(encoding="utf-8")))
