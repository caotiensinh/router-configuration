from __future__ import annotations

from enum import IntEnum
from typing import Iterable

from .tool_registry import MikroTikToolMode, MikroTikToolSpec


class ToolRisk(IntEnum):
    NONE = 0
    LOW = 1
    HIGH = 2
    CRITICAL = 3


def classify_tool_risk(tool: MikroTikToolSpec) -> ToolRisk:
    if tool.mode is MikroTikToolMode.READ_ONLY:
        return ToolRisk.NONE
    if tool.mode is MikroTikToolMode.TEST:
        return ToolRisk.LOW
    if tool.mode is MikroTikToolMode.CAPTURE:
        return ToolRisk.HIGH
    if tool.mode is MikroTikToolMode.DESTRUCTIVE:
        return ToolRisk.CRITICAL
    if tool.mode is MikroTikToolMode.WRITE:
        return ToolRisk.CRITICAL if tool.management_critical else ToolRisk.HIGH
    raise ValueError(f"unsupported MikroTik tool mode: {tool.mode}")


def classify_plan_risk(tools: Iterable[MikroTikToolSpec]) -> ToolRisk:
    risks = tuple(classify_tool_risk(tool) for tool in tools)
    return max(risks, default=ToolRisk.NONE)
