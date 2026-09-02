from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Any, Mapping

_CAPABILITY_SURFACES: dict[str, tuple[str, ...]] = {
    "identity": ("system_identity", "system_resource"),
    "interfaces": ("interfaces", "ip_addresses"),
    "routing": ("ip_routes", "routing_tables"),
    "firewall": ("firewall_filter", "firewall_nat"),
    "wireguard": ("wireguard_interfaces", "wireguard_peers"),
    "qos": ("queue_simple", "queue_tree"),
}

_VERSION_RE = re.compile(
    r"^\s*(?P<major>\d+)\.(?P<minor>\d+)(?:\.(?P<patch>\d+))?"
    r"(?P<suffix>(?:alpha|beta|rc)\d+)?",
    re.IGNORECASE,
)


@dataclass(frozen=True)
class RouterOSVersion:
    major: int
    minor: int
    patch: int = 0
    suffix: str = ""

    @property
    def is_v7_or_newer(self) -> bool:
        return self.major >= 7

    @property
    def supports_rest_read(self) -> bool:
        if self.major > 7:
            return True
        if self.major < 7:
            return False
        if self.minor > 1:
            return True
        if self.minor < 1:
            return False

        suffix = self.suffix.lower()
        if not suffix:
            return True
        if suffix.startswith("rc"):
            return True
        if suffix.startswith("beta"):
            number = int(suffix[4:] or "0")
            return number >= 4
        return False


def parse_routeros_version(value: str | None) -> RouterOSVersion | None:
    if not value:
        return None
    match = _VERSION_RE.match(value)
    if not match:
        return None
    return RouterOSVersion(
        major=int(match.group("major")),
        minor=int(match.group("minor")),
        patch=int(match.group("patch") or 0),
        suffix=match.group("suffix") or "",
    )


@dataclass(frozen=True)
class CapabilityAssessment:
    version_text: str | None
    rest_read_supported: bool
    capabilities: tuple[tuple[str, bool], ...]
    blockers: tuple[str, ...]
    warnings: tuple[str, ...]

    def as_dict(self) -> dict[str, Any]:
        return {
            "version": self.version_text,
            "rest_read_supported": self.rest_read_supported,
            "capabilities": dict(self.capabilities),
            "blockers": list(self.blockers),
            "warnings": list(self.warnings),
        }


def assess_routeros_capabilities(state: Mapping[str, Any]) -> CapabilityAssessment:
    platform = state.get("platform", {})
    if not isinstance(platform, Mapping):
        platform = {}

    version_text = platform.get("version")
    version = parse_routeros_version(str(version_text) if version_text is not None else None)
    missing = set(state.get("missing_surfaces", []))

    blockers: list[str] = []
    warnings: list[str] = []

    rest_read_supported = bool(version and version.supports_rest_read)
    if version is None:
        blockers.append("RouterOS version could not be parsed")
    elif not version.supports_rest_read:
        blockers.append("RouterOS version is below the supported REST read baseline")

    capabilities: list[tuple[str, bool]] = []
    for name, surfaces in _CAPABILITY_SURFACES.items():
        supported = all(surface not in missing for surface in surfaces)
        capabilities.append((name, supported))
        if not supported:
            warnings.append(
                f"{name} discovery is incomplete: missing "
                + ", ".join(surface for surface in surfaces if surface in missing)
            )

    if not dict(capabilities).get("identity", False):
        blockers.append("identity/resource discovery is incomplete")

    return CapabilityAssessment(
        version_text=str(version_text) if version_text is not None else None,
        rest_read_supported=rest_read_supported,
        capabilities=tuple(capabilities),
        blockers=tuple(blockers),
        warnings=tuple(warnings),
    )
