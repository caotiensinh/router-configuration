from __future__ import annotations

from dataclasses import dataclass
import re
from typing import Any, Mapping

from .tool_registry import MikroTikToolMode, MikroTikTransport


_NAME = re.compile(r"^mikrotik\.[a-z0-9_.-]+$")
_ACTION = re.compile(r"^[a-z][a-z0-9_-]*$")
_FORBIDDEN_FIELDS = {"command", "commands", "cli", "script", "password", "secret", "private_key", "token"}


@dataclass(frozen=True)
class NormalizedRouterOSOperation:
    name: str
    routeros_path: str
    action: str
    mode: MikroTikToolMode
    preferred_transport: MikroTikTransport
    required_policies: tuple[str, ...]
    features: tuple[str, ...]
    documentation_url: str
    knowledge_id: str
    management_critical: bool = False
    continuous: bool = False


def normalize_operation(payload: Mapping[str, Any]) -> NormalizedRouterOSOperation:
    forbidden = sorted(str(key) for key in payload if str(key).lower() in _FORBIDDEN_FIELDS)
    if forbidden:
        raise ValueError("normalized operation must not contain raw CLI/secrets: " + ", ".join(forbidden))
    if payload.get("schema_version") != "mikrotik-normalized-operation/1":
        raise ValueError("unsupported normalized operation schema")
    if payload.get("vendor") != "mikrotik":
        raise ValueError("normalized operation vendor must be mikrotik")
    name = str(payload.get("name") or "").strip()
    path = str(payload.get("routeros_path") or "").strip()
    action = str(payload.get("action") or "").strip().lower()
    docs = str(payload.get("documentation_url") or "").strip()
    knowledge_id = str(payload.get("knowledge_id") or "").strip()
    if not _NAME.fullmatch(name):
        raise ValueError("invalid MikroTik tool name")
    if not path.startswith("/") or any(ch.isspace() for ch in path):
        raise ValueError("invalid RouterOS path")
    if not _ACTION.fullmatch(action):
        raise ValueError("invalid normalized action")
    if not docs.startswith("https://manual.mikrotik.com/") or not knowledge_id:
        raise ValueError("operation requires current official MikroTik provenance")
    return NormalizedRouterOSOperation(
        name=name,
        routeros_path=path,
        action=action,
        mode=MikroTikToolMode(str(payload.get("mode") or "")),
        preferred_transport=MikroTikTransport(str(payload.get("preferred_transport") or "")),
        required_policies=tuple(str(item) for item in payload.get("required_policies", ())),
        features=tuple(str(item) for item in payload.get("features", ())),
        documentation_url=docs,
        knowledge_id=knowledge_id,
        management_critical=payload.get("management_critical") is True,
        continuous=payload.get("continuous") is True,
    )
