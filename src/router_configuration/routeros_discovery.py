from __future__ import annotations

import base64
import json
import ssl
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass
from typing import Any, Mapping, Protocol

READ_SURFACES: dict[str, str] = {
    "system_identity": "system/identity",
    "system_resource": "system/resource",
    "interfaces": "interface",
    "ip_addresses": "ip/address",
    "ip_routes": "ip/route",
    "routing_tables": "routing/table",
    "firewall_filter": "ip/firewall/filter",
    "firewall_nat": "ip/firewall/nat",
    "wireguard_interfaces": "interface/wireguard",
    "wireguard_peers": "interface/wireguard/peers",
    "queue_simple": "queue/simple",
    "queue_tree": "queue/tree",
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


class ReadOnlySurfaceClient(Protocol):
    def get_surface(self, surface: str) -> Any: ...


@dataclass(frozen=True)
class RouterOSRestClient:
    """Minimal RouterOS REST reader.

    Only allowlisted GET requests are supported. There is deliberately no generic
    request method and no POST/PUT/PATCH/DELETE surface in this class.
    """

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
            raise ValueError(
                "plain HTTP is disabled; use HTTPS or explicitly allow insecure lab transport"
            )
        if not parsed.hostname:
            raise ValueError("RouterOS REST base_url must include a hostname")
        if parsed.username or parsed.password:
            raise ValueError("credentials must not be embedded in RouterOS REST base_url")
        if parsed.path not in {"", "/"} or parsed.query or parsed.fragment:
            raise ValueError("RouterOS REST base_url must be scheme://host[:port] without path/query/fragment")
        if not self.username:
            raise ValueError("RouterOS username must not be empty")

    def build_request(self, surface: str) -> urllib.request.Request:
        if surface not in READ_SURFACES:
            raise ValueError(f"surface is not in the read-only allowlist: {surface}")
        path = READ_SURFACES[surface]
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
            if self.verify_tls:
                context = ssl.create_default_context()
            else:
                context = ssl._create_unverified_context()  # noqa: SLF001 - explicit lab-only option
        with urllib.request.urlopen(
            request,
            timeout=self.timeout_seconds,
            context=context,
        ) as response:
            return json.loads(response.read().decode("utf-8"))


@dataclass(frozen=True)
class RouterOSDiscoveryReport:
    data: dict[str, Any]
    errors: dict[str, str]

    @property
    def successful_surfaces(self) -> tuple[str, ...]:
        return tuple(sorted(self.data))

    @property
    def failed_surfaces(self) -> tuple[str, ...]:
        return tuple(sorted(self.errors))


def _safe_error_code(exc: Exception) -> str:
    """Return a credential/URL-free error code suitable for evidence artifacts."""

    if isinstance(exc, urllib.error.HTTPError):
        return f"http_{exc.code}"
    if isinstance(exc, urllib.error.URLError):
        return "transport_error"
    if isinstance(exc, TimeoutError):
        return "timeout"
    if isinstance(exc, json.JSONDecodeError):
        return "invalid_json"
    return exc.__class__.__name__


class RouterOSDiscoveryCollector:
    """Collect only the approved RouterOS read surfaces."""

    def __init__(self, client: ReadOnlySurfaceClient) -> None:
        self._client = client

    def collect(self) -> dict[str, Any]:
        return {surface: self._client.get_surface(surface) for surface in READ_SURFACES}

    def collect_report(self) -> RouterOSDiscoveryReport:
        data: dict[str, Any] = {}
        errors: dict[str, str] = {}
        for surface in READ_SURFACES:
            try:
                data[surface] = self._client.get_surface(surface)
            except Exception as exc:  # noqa: BLE001 - boundary converts errors to safe codes
                errors[surface] = _safe_error_code(exc)
        return RouterOSDiscoveryReport(data=data, errors=errors)


def _is_secret_key(key: str) -> bool:
    lowered = key.lower()
    return any(token in lowered for token in _SECRET_KEY_TOKENS)


def _normalize_value(value: Any) -> Any:
    if isinstance(value, Mapping):
        normalized: dict[str, Any] = {}
        for key, item in value.items():
            key_text = str(key)
            if _is_secret_key(key_text):
                normalized[key_text] = "<redacted>"
            else:
                normalized[key_text] = _normalize_value(item)
        return normalized
    if isinstance(value, list):
        return [_normalize_value(item) for item in value]
    if isinstance(value, str):
        if value == "true":
            return True
        if value == "false":
            return False
    return value


def _records(value: Any) -> list[dict[str, Any]]:
    if value is None:
        return []
    if isinstance(value, Mapping):
        return [dict(_normalize_value(value))]
    if not isinstance(value, list):
        raise ValueError("RouterOS discovery surface must be a JSON object or list")
    records: list[dict[str, Any]] = []
    for item in value:
        if not isinstance(item, Mapping):
            raise ValueError("RouterOS discovery list entries must be JSON objects")
        records.append(dict(_normalize_value(item)))
    records.sort(
        key=lambda item: json.dumps(
            item, sort_keys=True, separators=(",", ":"), default=str
        )
    )
    return records


def normalize_routeros_snapshot(raw: Mapping[str, Any]) -> dict[str, Any]:
    """Convert raw RouterOS REST GET payloads into deterministic, redacted state."""

    unknown = sorted(set(raw) - set(READ_SURFACES))
    if unknown:
        raise ValueError(f"unknown RouterOS discovery surfaces: {', '.join(unknown)}")

    identity_rows = _records(raw.get("system_identity"))
    resource_rows = _records(raw.get("system_resource"))
    identity = identity_rows[0] if identity_rows else {}
    resource = resource_rows[0] if resource_rows else {}

    state = {
        "schema_version": "routeros-state/1",
        "platform": {
            "identity": identity.get("name"),
            "version": resource.get("version"),
            "board_name": resource.get("board-name"),
            "architecture": resource.get("architecture-name"),
        },
        "interfaces": _records(raw.get("interfaces")),
        "ip_addresses": _records(raw.get("ip_addresses")),
        "ip_routes": _records(raw.get("ip_routes")),
        "routing_tables": _records(raw.get("routing_tables")),
        "firewall": {
            "filter": _records(raw.get("firewall_filter")),
            "nat": _records(raw.get("firewall_nat")),
        },
        "wireguard": {
            "interfaces": _records(raw.get("wireguard_interfaces")),
            "peers": _records(raw.get("wireguard_peers")),
        },
        "qos": {
            "simple_queues": _records(raw.get("queue_simple")),
            "queue_tree": _records(raw.get("queue_tree")),
        },
        "missing_surfaces": sorted(set(READ_SURFACES) - set(raw)),
    }
    return state
