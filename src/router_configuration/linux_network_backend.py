from __future__ import annotations

import os
import shutil
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Mapping

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


class LinuxNetworkBackendError(ValueError):
    pass


def cap_net_admin_from_status(status_text: str) -> bool:
    for line in str(status_text or "").splitlines():
        if line.startswith("CapEff:"):
            _, value = line.split(":", 1)
            try:
                effective = int(value.strip(), 16)
            except ValueError as exc:
                raise LinuxNetworkBackendError("invalid CapEff value") from exc
            return bool(effective & (1 << _CAP_NET_ADMIN_BIT))
    return False


def _read_cap_net_admin(status_path: Path = Path("/proc/self/status")) -> bool:
    try:
        return cap_net_admin_from_status(status_path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError):
        return False


@dataclass(frozen=True)
class LinuxNetworkCapabilities:
    platform_linux: bool
    cap_net_admin: bool
    ip_tool_available: bool
    network_namespace_supported: bool
    veth_supported: bool
    bridge_supported: bool
    vlan_supported: bool
    unavailable_reasons: tuple[str, ...]

    def as_dict(self) -> dict[str, object]:
        return {
            "platform_linux": self.platform_linux,
            "cap_net_admin": self.cap_net_admin,
            "ip_tool_available": self.ip_tool_available,
            "network_namespace_supported": self.network_namespace_supported,
            "veth_supported": self.veth_supported,
            "bridge_supported": self.bridge_supported,
            "vlan_supported": self.vlan_supported,
            "unavailable_reasons": list(self.unavailable_reasons),
        }


@dataclass(frozen=True)
class LinuxNetworkBackendSelection:
    backend_kind: str
    evidence_ceiling: str
    unavailable_reasons: tuple[str, ...]
    kernel_namespace_validation_available: bool
    hardware_verified: bool = False
    production_write_authority: bool = False

    def as_dict(self) -> dict[str, object]:
        return {
            "backend_kind": self.backend_kind,
            "evidence_ceiling": self.evidence_ceiling,
            "unavailable_reasons": list(self.unavailable_reasons),
            "kernel_namespace_validation_available": self.kernel_namespace_validation_available,
            "hardware_verified": self.hardware_verified,
            "production_write_authority": self.production_write_authority,
        }


def probe_linux_network_capabilities(
    *,
    feature_support: Mapping[str, bool] | None = None,
) -> LinuxNetworkCapabilities:
    """Observe non-mutating runtime prerequisites.

    veth/bridge/VLAN support is fail-closed unless an external probe explicitly
    supplies those observations. This function never escalates privileges or
    mutates host networking.
    """
    support = dict(feature_support or {})
    linux = sys.platform.startswith("linux")
    observed = {
        "platform_linux": linux,
        "cap_net_admin": linux and _read_cap_net_admin(),
        "ip_tool_available": linux and shutil.which("ip") is not None,
        "network_namespace_supported": linux and os.path.exists("/proc/self/ns/net"),
        "veth_supported": bool(support.get("veth_supported", False)),
        "bridge_supported": bool(support.get("bridge_supported", False)),
        "vlan_supported": bool(support.get("vlan_supported", False)),
    }
    reasons = tuple(f"{name}=false" for name in _REQUIRED if not observed[name])
    return LinuxNetworkCapabilities(**observed, unavailable_reasons=reasons)


def select_linux_network_backend(capabilities: LinuxNetworkCapabilities) -> LinuxNetworkBackendSelection:
    if not isinstance(capabilities, LinuxNetworkCapabilities):
        raise LinuxNetworkBackendError("capabilities must be LinuxNetworkCapabilities")
    values = capabilities.as_dict()
    ready = all(bool(values[name]) for name in _REQUIRED)
    if ready:
        return LinuxNetworkBackendSelection(
            backend_kind="KernelNamespaceBackend",
            evidence_ceiling="VIRTUAL_VERIFIED",
            unavailable_reasons=(),
            kernel_namespace_validation_available=True,
        )
    reasons = capabilities.unavailable_reasons or tuple(
        f"{name}=false" for name in _REQUIRED if not bool(values[name])
    )
    return LinuxNetworkBackendSelection(
        backend_kind="DeterministicUserSpaceBackend",
        evidence_ceiling="VIRTUAL_VERIFIED",
        unavailable_reasons=tuple(reasons),
        kernel_namespace_validation_available=False,
    )
