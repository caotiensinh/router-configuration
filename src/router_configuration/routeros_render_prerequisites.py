from __future__ import annotations

import base64
import json
import ssl
import urllib.parse
import urllib.request
from dataclasses import dataclass
from typing import Any, Mapping, Protocol


RENDER_READ_SURFACES: dict[str, str] = {
    "bridges": "interface/bridge",
    "bridge_ports": "interface/bridge/port",
    "bridge_vlans": "interface/bridge/vlan",
    "vlan_interfaces": "interface/vlan",
    "queue_types": "queue/type",
    "routing_rules": "routing/rule",
}

_SECRET_KEY_TOKENS = (
    "password",
    "private-key",
    "private_key",
    "preshared-key",
    "preshared_key",
    "psk",
    "secret",
    "token",
)


class RenderPrerequisiteSurfaceClient(Protocol):
    def get_surface(self, surface: str) -> Any: ...


@dataclass(frozen=True)
class RouterOSRenderPrerequisiteClient:
    """GET-only RouterOS client for renderer conflict/safety prerequisites."""

    base_url: str
    username: str
    password: str
    verify_tls: bool = True
    allow_insecure_transport: bool = False
    timeout_seconds: float = 10.0

    def __post_init__(self) -> None:
        parsed = urllib.parse.urlparse(self.base_url)
        if parsed.scheme not in {"https", "http"}:
            raise ValueError("RouterOS REST base_url must use http or https")
        if parsed.scheme != "https" and not self.allow_insecure_transport:
            raise ValueError("plain HTTP is disabled outside explicit lab mode")
        if not parsed.hostname:
            raise ValueError("RouterOS REST base_url must include a hostname")
        if parsed.username or parsed.password:
            raise ValueError("credentials must not be embedded in RouterOS REST base_url")
        if parsed.path not in {"", "/"} or parsed.query or parsed.fragment:
            raise ValueError("RouterOS REST base_url must be scheme://host[:port] only")
        if not self.username:
            raise ValueError("RouterOS username must not be empty")

    def build_request(self, surface: str) -> urllib.request.Request:
        if surface not in RENDER_READ_SURFACES:
            raise ValueError(f"surface is not in the renderer-prerequisite allowlist: {surface}")
        path = RENDER_READ_SURFACES[surface]
        url = f"{self.base_url.rstrip('/')}/rest/{path}"
        token = base64.b64encode(f"{self.username}:{self.password}".encode()).decode()
        return urllib.request.Request(
            url,
            headers={"Authorization": f"Basic {token}", "Accept": "application/json"},
            method="GET",
        )

    def get_surface(self, surface: str) -> Any:
        request = self.build_request(surface)
        context: ssl.SSLContext | None = None
        if request.full_url.startswith("https://"):
            context = ssl.create_default_context() if self.verify_tls else ssl._create_unverified_context()  # noqa: SLF001
        with urllib.request.urlopen(
            request,
            timeout=self.timeout_seconds,
            context=context,
        ) as response:
            return json.loads(response.read().decode("utf-8"))


@dataclass(frozen=True)
class RenderPrerequisiteReport:
    data: Mapping[str, Any]
    errors: Mapping[str, str]

    @property
    def ok(self) -> bool:
        return not self.errors and set(self.data) == set(RENDER_READ_SURFACES)


class RouterOSRenderPrerequisiteCollector:
    def __init__(self, client: RenderPrerequisiteSurfaceClient) -> None:
        self._client = client

    def collect_report(self) -> RenderPrerequisiteReport:
        data: dict[str, Any] = {}
        errors: dict[str, str] = {}
        for surface in RENDER_READ_SURFACES:
            try:
                data[surface] = self._client.get_surface(surface)
            except Exception as exc:  # noqa: BLE001 - evidence boundary emits only error class
                errors[surface] = exc.__class__.__name__
        return RenderPrerequisiteReport(data=data, errors=errors)


def _normalize_value(value: Any) -> Any:
    if isinstance(value, Mapping):
        result: dict[str, Any] = {}
        for raw_key, child in value.items():
            key = str(raw_key)
            if any(token in key.lower() for token in _SECRET_KEY_TOKENS):
                result[key] = "<redacted>"
            else:
                result[key] = _normalize_value(child)
        return result
    if isinstance(value, list):
        return [_normalize_value(child) for child in value]
    if isinstance(value, str):
        if value == "true":
            return True
        if value == "false":
            return False
    return value


def _records(value: Any, label: str) -> list[dict[str, Any]]:
    if value is None:
        return []
    rows = [value] if isinstance(value, Mapping) else value
    if not isinstance(rows, list):
        raise ValueError(f"{label} must be a RouterOS object or list")
    result: list[dict[str, Any]] = []
    for index, row in enumerate(rows):
        if not isinstance(row, Mapping):
            raise ValueError(f"{label}[{index}] must be an object")
        result.append(dict(_normalize_value(row)))
    result.sort(key=lambda row: json.dumps(row, sort_keys=True, separators=(",", ":"), default=str))
    return result


def normalize_render_prerequisites(raw: Mapping[str, Any]) -> dict[str, Any]:
    unknown = sorted(set(raw) - set(RENDER_READ_SURFACES))
    missing = sorted(set(RENDER_READ_SURFACES) - set(raw))
    if unknown:
        raise ValueError("unknown render prerequisite surfaces: " + ", ".join(unknown))
    if missing:
        raise ValueError("missing render prerequisite surfaces: " + ", ".join(missing))

    return {
        "schema_version": "routeros-render-prerequisites/1",
        "switching": {
            "bridges": _records(raw.get("bridges"), "bridges"),
            "bridge_ports": _records(raw.get("bridge_ports"), "bridge_ports"),
            "bridge_vlans": _records(raw.get("bridge_vlans"), "bridge_vlans"),
            "vlan_interfaces": _records(raw.get("vlan_interfaces"), "vlan_interfaces"),
        },
        "qos": {
            "queue_types": _records(raw.get("queue_types"), "queue_types"),
        },
        "policy_routing": {
            "rules": _records(raw.get("routing_rules"), "routing_rules"),
        },
        "read_only": True,
        "write_methods_present": False,
    }
