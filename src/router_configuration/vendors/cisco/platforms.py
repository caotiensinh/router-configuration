"""Cisco IOS XE platform/version admission primitives.

This module intentionally performs documentation-scope classification only. It
never infers feature support, license state, device state, or write authority.
Those facts must come from device discovery plus authoritative Cisco sources.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
import re
from typing import Final


class CiscoDeviceRole(str, Enum):
    ROUTER = "router"
    SWITCH = "switch"


@dataclass(frozen=True)
class CiscoPlatformFamily:
    family: str
    role: CiscoDeviceRole
    model_prefixes: tuple[str, ...]
    documentation_source_ids: tuple[str, ...]


@dataclass(frozen=True)
class CiscoPlatformDecision:
    status: str
    model: str
    iosxe_version: str
    family: str | None
    role: CiscoDeviceRole | None
    documentation_train: str | None
    documentation_source_ids: tuple[str, ...]
    read_only_candidate: bool
    write_authorized: bool = False
    physical_device_verified: bool = False


_FAMILIES: Final[tuple[CiscoPlatformFamily, ...]] = (
    CiscoPlatformFamily(
        "Catalyst 8000V",
        CiscoDeviceRole.ROUTER,
        ("C8000V", "CAT8000V"),
        ("CISCO-IOSXE-26-PROG", "CISCO-IOSXE-17.18-PROG"),
    ),
    CiscoPlatformFamily(
        "Catalyst 8200",
        CiscoDeviceRole.ROUTER,
        ("C8200",),
        ("CISCO-IOSXE-26-PROG", "CISCO-IOSXE-17.18-PROG"),
    ),
    CiscoPlatformFamily(
        "Catalyst 8300",
        CiscoDeviceRole.ROUTER,
        ("C8300",),
        ("CISCO-IOSXE-26-PROG", "CISCO-IOSXE-17.18-PROG"),
    ),
    CiscoPlatformFamily(
        "Catalyst 8500",
        CiscoDeviceRole.ROUTER,
        ("C8500",),
        ("CISCO-IOSXE-26-PROG", "CISCO-IOSXE-17.18-PROG"),
    ),
    CiscoPlatformFamily(
        "Catalyst 9200",
        CiscoDeviceRole.SWITCH,
        ("C9200",),
        ("CISCO-IOSXE-26-PROG", "CISCO-IOSXE-17.18-PROG"),
    ),
    CiscoPlatformFamily(
        "Catalyst 9300",
        CiscoDeviceRole.SWITCH,
        ("C9300",),
        (
            "CISCO-IOSXE-26-PROG",
            "CISCO-IOSXE-17.18-PROG",
            "CISCO-C9300-CONFIG-INDEX",
        ),
    ),
    CiscoPlatformFamily(
        "Catalyst 9400",
        CiscoDeviceRole.SWITCH,
        ("C9400",),
        ("CISCO-IOSXE-26-PROG", "CISCO-IOSXE-17.18-PROG"),
    ),
    CiscoPlatformFamily(
        "Catalyst 9500",
        CiscoDeviceRole.SWITCH,
        ("C9500",),
        ("CISCO-IOSXE-26-PROG", "CISCO-IOSXE-17.18-PROG"),
    ),
    CiscoPlatformFamily(
        "Catalyst 9600",
        CiscoDeviceRole.SWITCH,
        ("C9600",),
        ("CISCO-IOSXE-26-PROG", "CISCO-IOSXE-17.18-PROG"),
    ),
)

_DOCUMENTED_TRAINS: Final[dict[str, str]] = {
    "17.18": "CISCO-IOSXE-17.18-PROG",
    "26": "CISCO-IOSXE-26-PROG",
}


def platform_families() -> tuple[CiscoPlatformFamily, ...]:
    return _FAMILIES


def normalize_model(model: str) -> str:
    return re.sub(r"[^A-Z0-9]", "", model.upper())


def classify_platform(model: str) -> CiscoPlatformFamily | None:
    normalized = normalize_model(model)
    for family in _FAMILIES:
        if any(normalized.startswith(prefix) for prefix in family.model_prefixes):
            return family
    return None


def documentation_train(iosxe_version: str) -> str | None:
    match = re.match(r"^\s*(\d+)(?:\.(\d+))?", iosxe_version)
    if not match:
        return None
    major = match.group(1)
    minor = match.group(2)
    if major == "26":
        return "26"
    if major == "17" and minor == "18":
        return "17.18"
    return None


def assess_read_only_candidate(model: str, iosxe_version: str) -> CiscoPlatformDecision:
    family = classify_platform(model)
    if family is None:
        return CiscoPlatformDecision(
            status="UNVERIFIED_PLATFORM",
            model=model,
            iosxe_version=iosxe_version,
            family=None,
            role=None,
            documentation_train=None,
            documentation_source_ids=(),
            read_only_candidate=False,
        )

    train = documentation_train(iosxe_version)
    if train is None:
        return CiscoPlatformDecision(
            status="UNVERIFIED_VERSION",
            model=model,
            iosxe_version=iosxe_version,
            family=family.family,
            role=family.role,
            documentation_train=None,
            documentation_source_ids=family.documentation_source_ids,
            read_only_candidate=False,
        )

    train_source = _DOCUMENTED_TRAINS[train]
    if train_source not in family.documentation_source_ids:
        return CiscoPlatformDecision(
            status="UNVERIFIED_PLATFORM_VERSION_PAIR",
            model=model,
            iosxe_version=iosxe_version,
            family=family.family,
            role=family.role,
            documentation_train=train,
            documentation_source_ids=family.documentation_source_ids,
            read_only_candidate=False,
        )

    return CiscoPlatformDecision(
        status="DOCUMENTED_READ_ONLY_CANDIDATE",
        model=model,
        iosxe_version=iosxe_version,
        family=family.family,
        role=family.role,
        documentation_train=train,
        documentation_source_ids=family.documentation_source_ids,
        read_only_candidate=True,
    )
