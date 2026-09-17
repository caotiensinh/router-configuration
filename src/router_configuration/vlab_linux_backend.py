from __future__ import annotations

from dataclasses import dataclass
from typing import Mapping


class LinuxBackendCapabilityError(ValueError):
    pass


_CAP_NET_ADMIN_BIT = 12
_REQUIRED = (
    "platform_linux",
    "cap_net_admin",
    "ip_tool_available",
    "network_namespace_supported",
    "veth_supported",
    "bridge_supported",
    "vlan_supported",
)


def cap_net_admin_from_capeff(cap_eff_hex: str) -> bool:
    text = str(cap_eff_hex or "").strip().lower()
    if text.startswith("0x"):
        text = text[2:]
    if not text:
        raise LinuxBackendCapabilityError("CapEff value is required")
    try:
        value = int(text, 16)
    except ValueError as exc:
        raise LinuxBackendCapabilityError("CapEff must be hexadecimal") from exc
    return bool(value & (1 << _CAP_NET_ADMIN_BIT))


@dataclass(frozen=True)
class LinuxBackendSelection:
    backend_kind: str
    evidence_class: str
    kernel_namespace_validated: bool
    hardware_verified: bool
    missing_capabilities: tuple[str, ...]
    reason: str

    def as_dict(self) -> dict[str, object]:
        return {
            "backend_kind": self.backend_kind,
            "evidence_class": self.evidence_class,
            "kernel_namespace_validated": self.kernel_namespace_validated,
            "hardware_verified": self.hardware_verified,
            "missing_capabilities": list(self.missing_capabilities),
            "reason": self.reason,
            "production_write_authority": False,
            "privilege_escalation_attempted": False,
        }


def select_linux_network_backend(observed: Mapping[str, object]) -> LinuxBackendSelection:
    if not isinstance(observed, Mapping):
        raise LinuxBackendCapabilityError("observed capability facts must be a mapping")
    unknown = set(observed) - set(_REQUIRED)
    if unknown:
        raise LinuxBackendCapabilityError(f"unknown capability facts: {sorted(unknown)}")
    missing_fields = [name for name in _REQUIRED if name not in observed]
    if missing_fields:
        raise LinuxBackendCapabilityError(f"missing capability facts: {missing_fields}")
    if any(type(observed[name]) is not bool for name in _REQUIRED):
        raise LinuxBackendCapabilityError("capability facts must be booleans")

    unavailable = tuple(name for name in _REQUIRED if not observed[name])
    if unavailable:
        return LinuxBackendSelection(
            backend_kind="DeterministicUserSpaceBackend",
            evidence_class="VIRTUAL_VERIFIED",
            kernel_namespace_validated=False,
            hardware_verified=False,
            missing_capabilities=unavailable,
            reason="required Linux network capability unavailable; deterministic user-space fallback selected",
        )

    return LinuxBackendSelection(
        backend_kind="KernelNamespaceBackend",
        evidence_class="VIRTUAL_VERIFIED",
        kernel_namespace_validated=True,
        hardware_verified=False,
        missing_capabilities=(),
        reason="all required Linux namespace/veth/bridge/VLAN capabilities observed",
    )
