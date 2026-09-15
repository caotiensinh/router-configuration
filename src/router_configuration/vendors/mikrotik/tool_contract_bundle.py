from __future__ import annotations

from dataclasses import dataclass
import hashlib
import json
from typing import Iterable

from .catalog_validation import validate_tool_catalog
from .tool_registry import MikroTikToolSpec


@dataclass(frozen=True)
class ToolContractBundle:
    tool_names: tuple[str, ...]
    catalog_sha256: str

    def as_dict(self) -> dict[str, object]:
        return {
            "schema_version": "mikrotik-tool-contract-bundle/1",
            "tool_names": list(self.tool_names),
            "catalog_sha256": self.catalog_sha256,
            "write_authorized": False,
        }


def build_tool_contract_bundle(tools: Iterable[MikroTikToolSpec]) -> ToolContractBundle:
    catalog = tuple(sorted(tools, key=lambda tool: tool.name))
    findings = validate_tool_catalog(catalog)
    if findings:
        raise ValueError("tool catalog contract validation failed")
    payload = [tool.as_dict() for tool in catalog]
    raw = json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
    return ToolContractBundle(
        tool_names=tuple(tool.name for tool in catalog),
        catalog_sha256=hashlib.sha256(raw).hexdigest(),
    )
