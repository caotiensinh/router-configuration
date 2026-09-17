from __future__ import annotations

from dataclasses import dataclass
from typing import Mapping, Sequence
from urllib.parse import urlparse


class PortalAuthError(ValueError):
    pass


_AUTH_TYPES = frozenset(
    {
        "NO_AUTHENTICATION",
        "SIMPLE_PASSWORD",
        "HOTSPOT_VOUCHER",
        "HOTSPOT_LOCAL_USER",
        "HOTSPOT_SMS",
        "HOTSPOT_RADIUS",
        "HOTSPOT_FORM_AUTH",
        "RADIUS_SERVER",
        "EXTERNAL_LDAP_SERVER",
        "EXTERNAL_PORTAL_SERVER",
        "GOOGLE_AUTHENTICATION",
    }
)
_TARGET_KINDS = frozenset({"SSID", "LAN"})
_SECRET_MARKERS = ("password", "private_key", "preshared", "client_secret", "access_token", "refresh_token")
_OFFICIAL_HOST_SUFFIXES = ("omadanetworks.com", "tp-link.com")
_RADIUS_TYPES = frozenset({"HOTSPOT_RADIUS", "RADIUS_SERVER"})


def _safe_text(value: object, label: str) -> str:
    text = str(value or "").strip()
    if not text or any(c in text for c in ("\n", "\r", "\x00")):
        raise PortalAuthError(f"{label} must be a non-empty safe value")
    return text


def _reject_secrets(value: object, path: str = "portal") -> None:
    if isinstance(value, Mapping):
        for key, child in value.items():
            name = str(key).strip().lower()
            if any(marker in name for marker in _SECRET_MARKERS):
                raise PortalAuthError(f"{path} contains secret-bearing field: {key}")
            _reject_secrets(child, f"{path}.{key}")
    elif isinstance(value, (list, tuple)):
        for index, child in enumerate(value):
            _reject_secrets(child, f"{path}[{index}]")


def _official_sources(values: Sequence[str]) -> tuple[str, ...]:
    if not values:
        raise PortalAuthError("source_refs must not be empty")
    result: list[str] = []
    for raw in values:
        value = _safe_text(raw, "source_ref")
        parsed = urlparse(value)
        host = (parsed.hostname or "").lower()
        if parsed.scheme != "https" or not any(host == suffix or host.endswith(f".{suffix}") for suffix in _OFFICIAL_HOST_SUFFIXES):
            raise PortalAuthError("source_refs must be official TP-Link/Omada HTTPS URLs")
        result.append(value)
    if len(result) != len(set(result)):
        raise PortalAuthError("source_refs must be unique")
    return tuple(sorted(result))


@dataclass(frozen=True)
class PortalAuthPlan:
    controller_version: str
    target_kind: str
    target_id: str
    authentication_type: str
    source_refs: tuple[str, ...]
    controller_must_remain_online: bool
    radius_vlan_assignment_supported: bool | None

    def as_dict(self) -> dict[str, object]:
        return {
            "schema_version": "omada-portal-auth/1",
            "controller_version": self.controller_version,
            "target_kind": self.target_kind,
            "target_id": self.target_id,
            "authentication_type": self.authentication_type,
            "source_refs": list(self.source_refs),
            "controller_must_remain_online": self.controller_must_remain_online,
            "radius_vlan_assignment_supported": self.radius_vlan_assignment_supported,
            "evidence_class": "VENDOR_DOCUMENT_VERIFIED",
            "executable": False,
            "production_write_authority": False,
            "hardware_verified": False,
        }


def build_portal_auth_plan(
    *,
    controller_version: str,
    target_kind: str,
    target_id: str,
    authentication_type: str,
    source_refs: Sequence[str],
    extra: Mapping[str, object] | None = None,
) -> PortalAuthPlan:
    version = _safe_text(controller_version, "controller_version")
    target = _safe_text(target_kind, "target_kind").upper()
    if target not in _TARGET_KINDS:
        raise PortalAuthError("target_kind must be SSID or LAN")
    auth = _safe_text(authentication_type, "authentication_type").upper()
    if auth not in _AUTH_TYPES:
        raise PortalAuthError("authentication_type is not in the documented normalized set")
    identifier = _safe_text(target_id, "target_id")
    if extra is not None:
        _reject_secrets(extra)

    return PortalAuthPlan(
        controller_version=version,
        target_kind=target,
        target_id=identifier,
        authentication_type=auth,
        source_refs=_official_sources(source_refs),
        controller_must_remain_online=True,
        radius_vlan_assignment_supported=False if auth in _RADIUS_TYPES else None,
    )
