from __future__ import annotations

from dataclasses import dataclass, field
from ipaddress import ip_address
from types import MappingProxyType
from typing import Iterable, Mapping

from .types import Vendor


@dataclass(frozen=True)
class DeviceIdentity:
    device_id: str
    vendor: Vendor
    model: str
    management_address: str

    def __post_init__(self) -> None:
        if not self.device_id.strip():
            raise ValueError("device_id must not be empty")
        if not self.model.strip():
            raise ValueError("model must not be empty")
        ip_address(self.management_address)


@dataclass(frozen=True)
class DeviceCapabilities:
    features: frozenset[str] = field(default_factory=frozenset)

    @classmethod
    def from_iterable(cls, features: Iterable[str]) -> "DeviceCapabilities":
        normalized = frozenset(
            item.strip().lower() for item in features if item and item.strip()
        )
        return cls(normalized)

    def supports(self, feature: str) -> bool:
        return feature.strip().lower() in self.features

    def require(self, *features: str) -> None:
        missing = [name for name in features if not self.supports(name)]
        if missing:
            raise ValueError(f"device lacks required capabilities: {', '.join(missing)}")


@dataclass(frozen=True)
class NormalizedDevice:
    identity: DeviceIdentity
    capabilities: DeviceCapabilities
    firmware_version: str | None = None
    interfaces: Mapping[str, str] = field(default_factory=dict)

    def __post_init__(self) -> None:
        clean = {
            str(role).strip(): str(name).strip()
            for role, name in self.interfaces.items()
            if str(role).strip() and str(name).strip()
        }
        object.__setattr__(self, "interfaces", MappingProxyType(clean))

    def interface_for(self, role: str) -> str:
        try:
            return self.interfaces[role]
        except KeyError as exc:
            raise KeyError(f"interface role is not defined: {role}") from exc
