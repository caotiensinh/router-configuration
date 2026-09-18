from __future__ import annotations

from dataclasses import dataclass
from typing import Mapping, Sequence
from urllib.parse import urlparse


class IdsIpsContractError(ValueError):
    pass


_MODES = frozenset({"IDS", "IPS"})
_LEVELS = frozenset({"LOW", "MEDIUM", "HIGH", "CUSTOM"})
_OFFICIAL_HOST_SUFFIXES = ("omadanetworks.com", "tp-link.com")
_FORBIDDEN_SCOPE = frozenset({"*", "ANY", "ALL", "UNKNOWN", "UNSPECIFIED", "N/A"})
_SECRET_MARKERS = ("password", "private_key", "preshared", "client_secret", "access_token", "refresh_token", "secret")


def _safe(value: object, label: str) -> str:
    text = str(value or "").strip()
    if not text or any(ch in text for ch in ("\n", "\r", "\x00")):
        raise IdsIpsContractError(f"{label} must be a non-empty single-line value")
    return text


def _exact(value: object, label: str) -> str:
    text = _safe(value, label)
    if text.upper() in _FORBIDDEN_SCOPE or "*" in text:
        raise IdsIpsContractError(f"{label} requires exact applicability")
    return text


def _reject_secrets(value: object, path: str = "ids_ips") -> None:
    if isinstance(value, Mapping):
        for key, child in value.items():
            name = str(key).strip().lower()
            if any(marker in name for marker in _SECRET_MARKERS):
                raise IdsIpsContractError(f"{path} contains forbidden secret field: {key}")
            _reject_secrets(child, f"{path}.{key}")
    elif isinstance(value, (list, tuple)):
        for index, child in enumerate(value):
            _reject_secrets(child, f"{path}[{index}]")


def _official_sources(values: Sequence[str]) -> tuple[str, ...]:
    if not values:
        raise IdsIpsContractError("source_refs must not be empty")
    normalized: list[str] = []
    for raw in values:
        value = _safe(raw, "source_ref")
        parsed = urlparse(value)
        host = (parsed.hostname or "").lower()
        if parsed.scheme != "https" or not any(host == suffix or host.endswith("." + suffix) for suffix in _OFFICIAL_HOST_SUFFIXES):
            raise IdsIpsContractError("source_refs must be official TP-Link/Omada HTTPS URLs")
        normalized.append(value)
    if len(normalized) != len(set(normalized)):
        raise IdsIpsContractError("source_refs must be unique")
    return tuple(sorted(normalized))


@dataclass(frozen=True)
class IdsIpsPlan:
    controller_version: str
    model: str
    hardware_version: str
    firmware: str
    region: str
    mode: str
    security_level: str
    effective_time: str
    geo_enforcer: bool
    source_refs: tuple[str, ...]

    def as_dict(self) -> dict[str, object]:
        return {
            "schema_version": "omada-ids-ips/1",
            "controller_version": self.controller_version,
            "model": self.model,
            "hardware_version": self.hardware_version,
            "firmware": self.firmware,
            "region": self.region,
            "mode": self.mode,
            "security_level": self.security_level,
            "effective_time": self.effective_time,
            "geo_enforcer": self.geo_enforcer,
            "ids_reports_only": self.mode == "IDS",
            "ips_block_seconds": 300 if self.mode == "IPS" else None,
            "allow_list_supported": True,
            "block_list_supported": True,
            "signature_suppression_supported": True,
            "throughput_reduction_warning": True,
            "evidence_class": "VENDOR_DOCUMENT_VERIFIED",
            "executable": False,
            "production_write_authority": False,
            "hardware_verified": False,
            "source_refs": list(self.source_refs),
        }


def build_ids_ips_plan(
    *,
    controller_version: str,
    model: str,
    hardware_version: str,
    firmware: str,
    region: str,
    mode: str,
    security_level: str,
    effective_time: str,
    geo_enforcer: bool,
    source_refs: Sequence[str],
    verification_state: str,
    extra: Mapping[str, object] | None = None,
) -> IdsIpsPlan:
    if _safe(verification_state, "verification_state").upper() != "VENDOR_DOCUMENT_VERIFIED":
        raise IdsIpsContractError("IDS/IPS applicability requires vendor-document verification")
    normalized_mode = _safe(mode, "mode").upper()
    if normalized_mode not in _MODES:
        raise IdsIpsContractError("mode must be IDS or IPS")
    level = _safe(security_level, "security_level").upper()
    if level not in _LEVELS:
        raise IdsIpsContractError("security_level is unsupported")
    if type(geo_enforcer) is not bool:
        raise IdsIpsContractError("geo_enforcer must be boolean")
    if extra is not None:
        _reject_secrets(extra)
    return IdsIpsPlan(
        controller_version=_exact(controller_version, "controller_version"),
        model=_exact(model, "model"),
        hardware_version=_exact(hardware_version, "hardware_version"),
        firmware=_exact(firmware, "firmware"),
        region=_exact(region, "region"),
        mode=normalized_mode,
        security_level=level,
        effective_time=_safe(effective_time, "effective_time"),
        geo_enforcer=geo_enforcer,
        source_refs=_official_sources(source_refs),
    )
