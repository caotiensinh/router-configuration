from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Iterable
from urllib.parse import urlparse


class OpenApiRegistryError(ValueError):
    pass


_METHODS = frozenset({"GET", "POST"})
_AUTH_MODES = frozenset({"AUTHORIZATION_CODE", "CLIENT_CREDENTIALS"})
_PLATFORMS = frozenset({"HARDWARE_CONTROLLER", "SOFTWARE_CONTROLLER", "CLOUD_BASED_CONTROLLER"})
_SHA256 = re.compile(r"^[0-9a-f]{64}$")
_SAFE_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{1,127}$")
_OFFICIAL_HOST_SUFFIXES = ("omadanetworks.com", "tp-link.com")
_FORBIDDEN_SCOPE = frozenset({"*", "ANY", "ALL", "UNKNOWN", "UNSPECIFIED", "N/A"})


def _safe(value: object, label: str) -> str:
    text = str(value or "").strip()
    if not text or any(ch in text for ch in ("\n", "\r", "\x00")):
        raise OpenApiRegistryError(f"{label} must be a non-empty single-line value")
    return text


def _exact(value: object, label: str) -> str:
    text = _safe(value, label)
    if text.upper() in _FORBIDDEN_SCOPE or "*" in text:
        raise OpenApiRegistryError(f"{label} requires exact scope")
    return text


def _official_url(value: object) -> str:
    text = _safe(value, "source_url")
    parsed = urlparse(text)
    host = (parsed.hostname or "").lower()
    if parsed.scheme != "https" or not any(host == suffix or host.endswith("." + suffix) for suffix in _OFFICIAL_HOST_SUFFIXES):
        raise OpenApiRegistryError("source_url must be official TP-Link/Omada HTTPS")
    return text


@dataclass(frozen=True)
class OpenApiOperation:
    operation_id: str
    semantic_action: str
    http_method: str
    endpoint_path: str
    controller_platform: str
    controller_version: str
    auth_mode: str
    source_url: str
    source_sha256: str
    source_locator: str

    def key(self) -> tuple[str, str, str]:
        return (self.operation_id, self.controller_platform, self.controller_version)

    def as_dict(self) -> dict[str, object]:
        return {
            "schema_version": "omada-openapi-operation/1",
            "operation_id": self.operation_id,
            "semantic_action": self.semantic_action,
            "http_method": self.http_method,
            "endpoint_path": self.endpoint_path,
            "controller_platform": self.controller_platform,
            "controller_version": self.controller_version,
            "auth_mode": self.auth_mode,
            "source_url": self.source_url,
            "source_sha256": self.source_sha256,
            "source_locator": self.source_locator,
            "verification_state": "VENDOR_DOCUMENT_VERIFIED",
            "requires_access_token": True,
            "executable": False,
            "production_write_authority": False,
        }


def build_openapi_operation(
    *,
    operation_id: str,
    semantic_action: str,
    http_method: str,
    endpoint_path: str,
    controller_platform: str,
    controller_version: str,
    auth_mode: str,
    source_url: str,
    source_sha256: str,
    source_locator: str,
    verification_state: str,
) -> OpenApiOperation:
    identifier = _safe(operation_id, "operation_id")
    if not _SAFE_ID.fullmatch(identifier):
        raise OpenApiRegistryError("operation_id format is invalid")
    if _safe(verification_state, "verification_state").upper() != "VENDOR_DOCUMENT_VERIFIED":
        raise OpenApiRegistryError("operation requires vendor-document verification")
    method = _safe(http_method, "http_method").upper()
    if method not in _METHODS:
        raise OpenApiRegistryError("Omada Open API registry permits only documented GET/POST methods")
    path = _safe(endpoint_path, "endpoint_path")
    if not path.startswith("/") or " " in path or "{" in path or "}" in path or "*" in path:
        raise OpenApiRegistryError("endpoint_path must be an exact documented path, not a placeholder")
    platform = _safe(controller_platform, "controller_platform").upper()
    if platform not in _PLATFORMS:
        raise OpenApiRegistryError("unsupported controller_platform")
    auth = _safe(auth_mode, "auth_mode").upper()
    if auth not in _AUTH_MODES:
        raise OpenApiRegistryError("unsupported auth_mode")
    digest = str(source_sha256 or "").strip().lower()
    if not _SHA256.fullmatch(digest):
        raise OpenApiRegistryError("source_sha256 must be lowercase SHA-256")
    return OpenApiOperation(
        operation_id=identifier,
        semantic_action=_safe(semantic_action, "semantic_action"),
        http_method=method,
        endpoint_path=path,
        controller_platform=platform,
        controller_version=_exact(controller_version, "controller_version"),
        auth_mode=auth,
        source_url=_official_url(source_url),
        source_sha256=digest,
        source_locator=_safe(source_locator, "source_locator"),
    )


class OpenApiOperationRegistry:
    def __init__(self, operations: Iterable[OpenApiOperation] = ()) -> None:
        self._operations: dict[tuple[str, str, str], OpenApiOperation] = {}
        for operation in operations:
            self.add(operation)

    def add(self, operation: OpenApiOperation) -> None:
        if not isinstance(operation, OpenApiOperation):
            raise OpenApiRegistryError("registry accepts only OpenApiOperation")
        if operation.key() in self._operations:
            raise OpenApiRegistryError("duplicate exact operation scope")
        self._operations[operation.key()] = operation

    def exact_lookup(self, operation_id: str, *, controller_platform: str, controller_version: str) -> OpenApiOperation:
        key = (
            _safe(operation_id, "operation_id"),
            _safe(controller_platform, "controller_platform").upper(),
            _exact(controller_version, "controller_version"),
        )
        try:
            return self._operations[key]
        except KeyError as exc:
            raise OpenApiRegistryError("no exact verified Open API operation match") from exc

    def as_dict(self) -> dict[str, object]:
        rows = [self._operations[key].as_dict() for key in sorted(self._operations)]
        return {
            "schema_version": "omada-openapi-registry/1",
            "operations": rows,
            "operation_count": len(rows),
            "fallback_matching": False,
            "production_write_authority": False,
        }
