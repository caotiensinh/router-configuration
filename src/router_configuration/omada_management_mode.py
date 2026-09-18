from __future__ import annotations

from dataclasses import dataclass
from typing import Iterable
from urllib.parse import urlparse


class ManagementModeError(ValueError):
    pass


_CATEGORIES = frozenset({
    "BOTH_PERSIST_OFFLINE",
    "CONTROLLER_ONLY_REQUIRES_ONLINE",
    "STANDALONE_ONLY",
    "CONTROLLER_CONFIG_ONLY_PERSISTS_OFFLINE",
    "MODE_BEHAVIOR_DIFF",
})
_OFFICIAL_HOST_SUFFIXES = ("omadanetworks.com", "tp-link.com")
_FORBIDDEN_SCOPE = frozenset({"*", "ANY", "ALL", "UNKNOWN", "UNSPECIFIED", "N/A"})


def _safe(value: object, label: str) -> str:
    text = str(value or "").strip()
    if not text or any(ch in text for ch in ("\n", "\r", "\x00")):
        raise ManagementModeError(f"{label} must be a non-empty single-line value")
    return text


def _scope(value: object, label: str) -> str:
    text = _safe(value, label)
    if text.upper() in _FORBIDDEN_SCOPE or "*" in text:
        raise ManagementModeError(f"{label} must use an explicit documented scope")
    return text


def _official_url(value: object) -> str:
    text = _safe(value, "source_url")
    parsed = urlparse(text)
    host = (parsed.hostname or "").lower()
    if parsed.scheme != "https" or not any(host == suffix or host.endswith("." + suffix) for suffix in _OFFICIAL_HOST_SUFFIXES):
        raise ManagementModeError("source_url must be an official TP-Link/Omada HTTPS URL")
    return text


@dataclass(frozen=True)
class ManagementModeDifference:
    difference_id: str
    product_family: str
    applicability_scope: str
    feature: str
    category: str
    standalone_behavior: str
    controller_behavior: str
    controller_offline_behavior: str
    local_ui_access_when_controller_managed: bool
    source_url: str
    source_locator: str

    def key(self) -> tuple[str, str, str]:
        return (self.product_family, self.applicability_scope, self.feature)

    def as_dict(self) -> dict[str, object]:
        return {
            "schema_version": "omada-management-mode-difference/1",
            "difference_id": self.difference_id,
            "product_family": self.product_family,
            "applicability_scope": self.applicability_scope,
            "feature": self.feature,
            "category": self.category,
            "standalone_behavior": self.standalone_behavior,
            "controller_behavior": self.controller_behavior,
            "controller_offline_behavior": self.controller_offline_behavior,
            "local_ui_access_when_controller_managed": self.local_ui_access_when_controller_managed,
            "source_url": self.source_url,
            "source_locator": self.source_locator,
            "verification_state": "VENDOR_DOCUMENT_VERIFIED",
            "production_write_authority": False,
        }


def build_management_mode_difference(
    *,
    difference_id: str,
    product_family: str,
    applicability_scope: str,
    feature: str,
    category: str,
    standalone_behavior: str,
    controller_behavior: str,
    controller_offline_behavior: str,
    local_ui_access_when_controller_managed: bool,
    source_url: str,
    source_locator: str,
    verification_state: str,
) -> ManagementModeDifference:
    if _safe(verification_state, "verification_state").upper() != "VENDOR_DOCUMENT_VERIFIED":
        raise ManagementModeError("mode differences require vendor-document verification")
    normalized_category = _safe(category, "category").upper()
    if normalized_category not in _CATEGORIES:
        raise ManagementModeError("unsupported management-mode difference category")
    if type(local_ui_access_when_controller_managed) is not bool:
        raise ManagementModeError("local_ui_access_when_controller_managed must be boolean")
    return ManagementModeDifference(
        difference_id=_safe(difference_id, "difference_id"),
        product_family=_scope(product_family, "product_family"),
        applicability_scope=_scope(applicability_scope, "applicability_scope"),
        feature=_safe(feature, "feature"),
        category=normalized_category,
        standalone_behavior=_safe(standalone_behavior, "standalone_behavior"),
        controller_behavior=_safe(controller_behavior, "controller_behavior"),
        controller_offline_behavior=_safe(controller_offline_behavior, "controller_offline_behavior"),
        local_ui_access_when_controller_managed=local_ui_access_when_controller_managed,
        source_url=_official_url(source_url),
        source_locator=_safe(source_locator, "source_locator"),
    )


class ManagementModeRegistry:
    def __init__(self, entries: Iterable[ManagementModeDifference] = ()) -> None:
        self._entries: dict[tuple[str, str, str], ManagementModeDifference] = {}
        for entry in entries:
            self.add(entry)

    def add(self, entry: ManagementModeDifference) -> None:
        if not isinstance(entry, ManagementModeDifference):
            raise ManagementModeError("registry accepts only ManagementModeDifference")
        if entry.key() in self._entries:
            raise ManagementModeError("duplicate feature/scope difference")
        self._entries[entry.key()] = entry

    def exact_lookup(self, *, product_family: str, applicability_scope: str, feature: str) -> ManagementModeDifference:
        key = (_scope(product_family, "product_family"), _scope(applicability_scope, "applicability_scope"), _safe(feature, "feature"))
        try:
            return self._entries[key]
        except KeyError as exc:
            raise ManagementModeError("no exact verified management-mode difference") from exc

    def as_dict(self) -> dict[str, object]:
        rows = [self._entries[key].as_dict() for key in sorted(self._entries)]
        return {
            "schema_version": "omada-management-mode-registry/1",
            "entries": rows,
            "entry_count": len(rows),
            "fallback_matching": False,
            "production_write_authority": False,
        }
