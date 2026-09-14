from __future__ import annotations

from dataclasses import dataclass
import hashlib
import json
from typing import Iterable

from .normalized_operation import NormalizedRouterOSOperation
from .tool_registry import MikroTikToolSpec


@dataclass(frozen=True)
class ToolGenerationEvidence:
    knowledge_sha256: str
    normalized_input_sha256: str
    generated_catalog_sha256: str
    generated_tool_names: tuple[str, ...]

    def as_dict(self) -> dict[str, object]:
        return {
            "schema_version": "mikrotik-tool-generation-evidence/1",
            "knowledge_sha256": self.knowledge_sha256,
            "normalized_input_sha256": self.normalized_input_sha256,
            "generated_catalog_sha256": self.generated_catalog_sha256,
            "generated_tool_names": list(self.generated_tool_names),
            "write_authorized": False,
        }


def _digest(payload: object) -> str:
    raw = json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
    return hashlib.sha256(raw).hexdigest()


def build_generation_evidence(
    *,
    operations: Iterable[NormalizedRouterOSOperation],
    tools: Iterable[MikroTikToolSpec],
    knowledge_sha256: str,
) -> ToolGenerationEvidence:
    ops = tuple(sorted(operations, key=lambda item: item.name))
    generated = tuple(sorted(tools, key=lambda item: item.name))
    op_names = tuple(item.name for item in ops)
    tool_names = tuple(item.name for item in generated)
    if op_names != tool_names:
        raise ValueError("generated tools do not exactly match normalized operation identities")
    if len(knowledge_sha256) != 64 or any(ch not in "0123456789abcdef" for ch in knowledge_sha256):
        raise ValueError("knowledge_sha256 must be lowercase SHA-256")
    op_payload = [
        {
            "name": item.name,
            "routeros_path": item.routeros_path,
            "action": item.action,
            "mode": item.mode.value,
            "preferred_transport": item.preferred_transport.value,
            "required_policies": list(item.required_policies),
            "features": list(item.features),
            "documentation_url": item.documentation_url,
            "knowledge_id": item.knowledge_id,
            "management_critical": item.management_critical,
            "continuous": item.continuous,
        }
        for item in ops
    ]
    return ToolGenerationEvidence(
        knowledge_sha256=knowledge_sha256,
        normalized_input_sha256=_digest(op_payload),
        generated_catalog_sha256=_digest([item.as_dict() for item in generated]),
        generated_tool_names=tool_names,
    )
