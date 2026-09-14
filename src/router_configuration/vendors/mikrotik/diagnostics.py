from __future__ import annotations

from dataclasses import dataclass
from typing import Iterable

from .tool_registry import MikroTikToolMode, MikroTikToolSpec, select_tools


@dataclass(frozen=True)
class DiagnosticPlan:
    features: tuple[str, ...]
    tools: tuple[MikroTikToolSpec, ...]

    def as_dict(self) -> dict[str, object]:
        return {
            "schema_version": "mikrotik-diagnostic-plan/1",
            "features": list(self.features),
            "tools": [tool.as_dict() for tool in self.tools],
            "configuration_mutation_allowed": False,
        }


def build_diagnostic_plan(
    features: Iterable[str],
    *,
    include_capture: bool = False,
) -> DiagnosticPlan:
    """Select the minimum registered read/test tools for an investigation.

    The planner never invents RouterOS commands and never returns write tools.
    Packet capture is a separate opt-in because it requires elevated `sniff`
    privilege in RouterOS.
    """

    normalized = tuple(sorted({str(item).strip().lower() for item in features if str(item).strip()}))
    tools = select_tools(normalized, include_writes=False, include_capture=include_capture)
    forbidden = {
        tool.name
        for tool in tools
        if tool.mode in {MikroTikToolMode.WRITE, MikroTikToolMode.DESTRUCTIVE}
    }
    if forbidden:
        raise ValueError("diagnostic plan unexpectedly contains mutating tools")
    return DiagnosticPlan(features=normalized, tools=tools)
