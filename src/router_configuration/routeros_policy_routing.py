from __future__ import annotations

import base64
import json
import ssl
import urllib.request
from dataclasses import dataclass
from typing import Any, Mapping, Protocol

from .routeros_discovery import RouterOSRestClient


_POLICY_ROUTING_PATH = "routing/rule"
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


class PolicyRoutingReader(Protocol):
    def read_rules(self) -> Any: ...


@dataclass(frozen=True)
class RouterOSPolicyRoutingRestReader:
    """Fixed-path read-only RouterOS policy-routing prerequisite reader.

    This intentionally does not expose a generic request or path argument. It
    can only issue GET /rest/routing/rule using an already validated
    RouterOSRestClient connection policy. No mutation method exists here.
    """

    client: RouterOSRestClient

    def build_request(self) -> urllib.request.Request:
        url = f"{self.client.base_url.rstrip('/')}/rest/{_POLICY_ROUTING_PATH}"
        token = base64.b64encode(
            f"{self.client.username}:{self.client.password}".encode()
        ).decode()
        return urllib.request.Request(
            url,
            headers={
                "Authorization": f"Basic {token}",
                "Accept": "application/json",
            },
            method="GET",
        )

    def read_rules(self) -> Any:
        request = self.build_request()
        context: ssl.SSLContext | None = None
        if request.full_url.startswith("https://"):
            if self.client.verify_tls:
                context = ssl.create_default_context()
            else:
                context = ssl._create_unverified_context()  # noqa: SLF001 - explicit lab-only mode inherited from validated client
        with urllib.request.urlopen(
            request,
            timeout=self.client.timeout_seconds,
            context=context,
        ) as response:
            return json.loads(response.read().decode("utf-8"))


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
        rows = [dict(_normalize_value(value))]
    elif isinstance(value, list):
        rows = []
        for item in value:
            if not isinstance(item, Mapping):
                raise ValueError("RouterOS routing-rule response entries must be objects")
            rows.append(dict(_normalize_value(item)))
    else:
        raise ValueError("RouterOS routing-rule response must be an object or list")
    rows.sort(
        key=lambda item: json.dumps(
            item,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=False,
            default=str,
        )
    )
    return rows


@dataclass(frozen=True)
class PolicyRoutingPrerequisites:
    rules: tuple[Mapping[str, Any], ...]

    def as_dict(self) -> dict[str, Any]:
        return {
            "schema_version": "routeros-render-prerequisites/1",
            "policy_routing": {
                "rules": [dict(item) for item in self.rules],
            },
            "source": "routeros_rest_get_routing_rule",
            "read_transport_used": True,
            "write_transport_present": False,
            "write_authorized": False,
        }


def collect_policy_routing_prerequisites(
    reader: PolicyRoutingReader,
) -> PolicyRoutingPrerequisites:
    """Collect deterministic policy-routing prerequisite state without writes."""

    return PolicyRoutingPrerequisites(rules=tuple(_records(reader.read_rules())))
