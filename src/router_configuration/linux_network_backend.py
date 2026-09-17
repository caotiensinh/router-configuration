from __future__ import annotations

import os
import re
import shutil
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Callable, Mapping, Sequence

from router_configuration.test_lab import StandardLabTopology

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
_LAB_ID = re.compile(r"^[a-z0-9][a-z0-9-]{0,30}$")


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


def _read_ip_link_help(ip_path: str) -> str:
    try:
        proc = subprocess.run(
            [ip_path, "link", "help"],
            check=False,
            capture_output=True,
            text=True,
            timeout=3,
        )
    except (OSError, subprocess.SubprocessError):
        return ""
    return f"{proc.stdout}\n{proc.stderr}".lower()


def _help_supports(help_text: str, kind: str) -> bool:
    text = str(help_text or "").lower()
    return bool(re.search(rf"(?<![a-z0-9_-]){re.escape(kind.lower())}(?![a-z0-9_-])", text))


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


@dataclass(frozen=True)
class KernelNamespacePlan:
    lab_id: str
    namespace: str
    vlan_id: int
    topology_sha256: str
    setup_commands: tuple[tuple[str, ...], ...]
    cleanup_commands: tuple[tuple[str, ...], ...]

    def as_dict(self) -> dict[str, object]:
        return {
            "lab_id": self.lab_id,
            "namespace": self.namespace,
            "vlan_id": self.vlan_id,
            "topology_sha256": self.topology_sha256,
            "setup_commands": [list(item) for item in self.setup_commands],
            "cleanup_commands": [list(item) for item in self.cleanup_commands],
            "evidence_ceiling": "VIRTUAL_VERIFIED",
            "physical_hardware_claimed": False,
            "production_write_authority": False,
        }


def probe_linux_network_capabilities(
    *,
    feature_support: Mapping[str, bool] | None = None,
    ip_link_help_text: str | None = None,
) -> LinuxNetworkCapabilities:
    """Observe prerequisites without changing network state or escalating privileges."""
    linux = sys.platform.startswith("linux")
    ip_path = shutil.which("ip") if linux else None
    help_text = ""
    if ip_path:
        help_text = ip_link_help_text if ip_link_help_text is not None else _read_ip_link_help(ip_path)
    support = dict(feature_support or {})

    def feature(name: str, kind: str) -> bool:
        if name in support:
            return bool(support[name])
        return bool(ip_path and _help_supports(help_text, kind))

    observed = {
        "platform_linux": linux,
        "cap_net_admin": linux and _read_cap_net_admin(),
        "ip_tool_available": ip_path is not None,
        "network_namespace_supported": linux and ip_path is not None and os.path.exists("/proc/self/ns/net"),
        "veth_supported": feature("veth_supported", "veth"),
        "bridge_supported": feature("bridge_supported", "bridge"),
        "vlan_supported": feature("vlan_supported", "vlan"),
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


def build_kernel_namespace_plan(*, lab_id: str = "omada-vlab12", vlan_id: int = 120) -> KernelNamespacePlan:
    ident = str(lab_id or "").strip().lower()
    if not _LAB_ID.fullmatch(ident):
        raise LinuxNetworkBackendError("lab_id must be a safe lowercase lab identifier")
    if not isinstance(vlan_id, int) or isinstance(vlan_id, bool) or not 2 <= vlan_id <= 4094:
        raise LinuxNetworkBackendError("vlan_id must be in 2..4094")

    topology = StandardLabTopology.build().as_dict()
    namespace = f"{ident}-ns"
    host_if = "ov12-host"
    peer_if = "ov12-peer"
    bridge_if = "ov12-br"
    vlan_if = f"ov12-v{vlan_id}"
    if len(vlan_if) > 15:
        raise LinuxNetworkBackendError("derived VLAN interface name exceeds Linux IFNAMSIZ")

    setup = (
        ("ip", "netns", "add", namespace),
        ("ip", "link", "add", host_if, "type", "veth", "peer", "name", peer_if),
        ("ip", "link", "set", peer_if, "netns", namespace),
        ("ip", "netns", "exec", namespace, "ip", "link", "add", bridge_if, "type", "bridge"),
        ("ip", "netns", "exec", namespace, "ip", "link", "set", peer_if, "master", bridge_if),
        ("ip", "netns", "exec", namespace, "ip", "link", "add", "link", bridge_if, "name", vlan_if, "type", "vlan", "id", str(vlan_id)),
        ("ip", "link", "set", host_if, "up"),
        ("ip", "netns", "exec", namespace, "ip", "link", "set", "lo", "up"),
        ("ip", "netns", "exec", namespace, "ip", "link", "set", peer_if, "up"),
        ("ip", "netns", "exec", namespace, "ip", "link", "set", bridge_if, "up"),
        ("ip", "netns", "exec", namespace, "ip", "link", "set", vlan_if, "up"),
    )
    cleanup = (
        ("ip", "netns", "del", namespace),
        ("ip", "link", "del", host_if),
    )
    return KernelNamespacePlan(
        lab_id=ident,
        namespace=namespace,
        vlan_id=vlan_id,
        topology_sha256=str(topology["topology_sha256"]),
        setup_commands=setup,
        cleanup_commands=cleanup,
    )


def _validate_owned_command(command: Sequence[str]) -> tuple[str, ...]:
    item = tuple(str(part) for part in command)
    if not item or item[0] != "ip":
        raise LinuxNetworkBackendError("kernel backend permits only bounded ip commands")
    if any(part in {"sudo", "su", "sh", "bash", "-c"} for part in item):
        raise LinuxNetworkBackendError("shell or privilege-escalation command is forbidden")
    return item


def _default_runner(command: Sequence[str]) -> None:
    subprocess.run(list(_validate_owned_command(command)), check=True, capture_output=True, text=True, timeout=10)


class KernelNamespaceBackend:
    backend_kind = "KernelNamespaceBackend"
    evidence_ceiling = "VIRTUAL_VERIFIED"
    hardware_verified = False
    production_write_authority = False

    def __init__(
        self,
        capabilities: LinuxNetworkCapabilities,
        *,
        plan: KernelNamespacePlan | None = None,
        runner: Callable[[Sequence[str]], object] | None = None,
    ) -> None:
        selection = select_linux_network_backend(capabilities)
        if selection.backend_kind != self.backend_kind:
            raise LinuxNetworkBackendError("kernel namespace backend requires all observed capabilities")
        self.capabilities = capabilities
        self.plan = plan or build_kernel_namespace_plan()
        self._runner = runner or _default_runner
        self._active = False

    def apply(self, *, explicit_lab_scope: bool = False) -> dict[str, object]:
        if not explicit_lab_scope:
            raise LinuxNetworkBackendError("host network mutation requires explicit_lab_scope=true")
        if self._active:
            raise LinuxNetworkBackendError("kernel namespace lab is already active")
        executed: list[tuple[str, ...]] = []
        try:
            for command in self.plan.setup_commands:
                safe = _validate_owned_command(command)
                self._runner(safe)
                executed.append(safe)
        except Exception:
            for command in self.plan.cleanup_commands:
                try:
                    self._runner(_validate_owned_command(command))
                except Exception:
                    pass
            raise
        self._active = True
        return {
            "backend_kind": self.backend_kind,
            "topology_sha256": self.plan.topology_sha256,
            "commands_executed": len(executed),
            "kernel_namespace_validation_executed": True,
            "evidence_ceiling": self.evidence_ceiling,
            "hardware_verified": False,
            "production_write_authority": False,
        }

    def cleanup(self, *, explicit_lab_scope: bool = False) -> dict[str, object]:
        if not explicit_lab_scope:
            raise LinuxNetworkBackendError("host network cleanup requires explicit_lab_scope=true")
        attempted = 0
        for command in self.plan.cleanup_commands:
            attempted += 1
            try:
                self._runner(_validate_owned_command(command))
            except Exception:
                pass
        self._active = False
        return {
            "backend_kind": self.backend_kind,
            "cleanup_commands_attempted": attempted,
            "active": False,
            "evidence_ceiling": self.evidence_ceiling,
            "hardware_verified": False,
            "production_write_authority": False,
        }


class DeterministicUserSpaceBackend:
    backend_kind = "DeterministicUserSpaceBackend"
    evidence_ceiling = "VIRTUAL_VERIFIED"
    hardware_verified = False
    production_write_authority = False

    def __init__(self, capabilities: LinuxNetworkCapabilities) -> None:
        selection = select_linux_network_backend(capabilities)
        if selection.backend_kind != self.backend_kind:
            raise LinuxNetworkBackendError("user-space fallback is only selected when kernel prerequisites are incomplete")
        self.capabilities = capabilities
        self.selection = selection
        self.topology = StandardLabTopology.build()

    def materialize(self) -> dict[str, object]:
        topology = self.topology.as_dict()
        return {
            "backend_kind": self.backend_kind,
            "topology": topology,
            "logical_resources": ["namespace", "veth_pair", "bridge", "vlan_subinterface"],
            "unavailable_reasons": list(self.selection.unavailable_reasons),
            "kernel_namespace_validation_executed": False,
            "deterministic_user_space_fallback": True,
            "evidence_ceiling": self.evidence_ceiling,
            "hardware_verified": False,
            "production_write_authority": False,
        }


def build_linux_network_backend(
    capabilities: LinuxNetworkCapabilities,
    *,
    runner: Callable[[Sequence[str]], object] | None = None,
) -> KernelNamespaceBackend | DeterministicUserSpaceBackend:
    selection = select_linux_network_backend(capabilities)
    if selection.backend_kind == "KernelNamespaceBackend":
        return KernelNamespaceBackend(capabilities, runner=runner)
    return DeterministicUserSpaceBackend(capabilities)
