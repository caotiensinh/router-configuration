from __future__ import annotations

from dataclasses import dataclass
from typing import Iterable

from .tool_registry import MikroTikToolMode, MikroTikToolSpec, MikroTikTransport


@dataclass(frozen=True)
class CatalogFinding:
    code: str
    tool_name: str
    detail: str


def validate_tool_catalog(tools: Iterable[MikroTikToolSpec]) -> tuple[CatalogFinding, ...]:
    catalog = tuple(tools)
    findings: list[CatalogFinding] = []
    seen: set[str] = set()
    for tool in catalog:
        if tool.name in seen:
            findings.append(CatalogFinding("duplicate_tool_name", tool.name, "tool name must be unique"))
        seen.add(tool.name)
        if not tool.documentation_url.startswith("https://manual.mikrotik.com/"):
            findings.append(CatalogFinding("non_primary_documentation", tool.name, "tool must reference current official MikroTik manual"))
        if tool.continuous and tool.preferred_transport is MikroTikTransport.REST:
            findings.append(CatalogFinding("continuous_rest_forbidden", tool.name, "continuous tools must not prefer REST"))
        if tool.mode is MikroTikToolMode.CAPTURE and "sniff" not in tool.required_policies:
            findings.append(CatalogFinding("capture_missing_sniff_policy", tool.name, "capture tool requires separate sniff privilege"))
        if tool.mutates_configuration and "write" not in tool.required_policies:
            findings.append(CatalogFinding("write_policy_missing", tool.name, "mutating tool must declare write privilege"))
        if tool.mutates_configuration and not tool.requires_explicit_write_gate:
            findings.append(CatalogFinding("write_gate_missing", tool.name, "mutating tool must require explicit write gate"))
    return tuple(findings)
