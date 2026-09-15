from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from typing import Iterable

from .tool_registry import MikroTikToolMode, MikroTikToolSpec


class PrivilegeProfileKind(str, Enum):
    READ_ONLY = "read_only"
    DIAGNOSTIC = "diagnostic"
    CAPTURE = "capture"
    CONFIGURATION = "configuration"


@dataclass(frozen=True)
class PrivilegeProfile:
    kind: PrivilegeProfileKind
    policies: tuple[str, ...]
    tool_names: tuple[str, ...]

    @property
    def unrestricted_admin(self) -> bool:
        return False


def build_privilege_profile(kind: PrivilegeProfileKind, tools: Iterable[MikroTikToolSpec]) -> PrivilegeProfile:
    selected = tuple(tools)
    allowed_modes = {
        PrivilegeProfileKind.READ_ONLY: {MikroTikToolMode.READ_ONLY},
        PrivilegeProfileKind.DIAGNOSTIC: {MikroTikToolMode.READ_ONLY, MikroTikToolMode.TEST},
        PrivilegeProfileKind.CAPTURE: {MikroTikToolMode.READ_ONLY, MikroTikToolMode.TEST, MikroTikToolMode.CAPTURE},
        PrivilegeProfileKind.CONFIGURATION: {MikroTikToolMode.READ_ONLY, MikroTikToolMode.TEST, MikroTikToolMode.WRITE},
    }[kind]
    disallowed = sorted(tool.name for tool in selected if tool.mode not in allowed_modes)
    if disallowed:
        raise ValueError("tools exceed requested privilege profile: " + ", ".join(disallowed))
    policies = tuple(sorted({policy for tool in selected for policy in tool.required_policies}))
    return PrivilegeProfile(kind=kind, policies=policies, tool_names=tuple(sorted(tool.name for tool in selected)))
