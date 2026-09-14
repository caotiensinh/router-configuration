from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from typing import Iterable, Mapping

from .mikrotik_docs import topic_url


class MikroTikToolMode(str, Enum):
    READ_ONLY = "read_only"
    TEST = "test"
    CAPTURE = "capture"
    WRITE = "write"
    DESTRUCTIVE = "destructive"


class MikroTikTransport(str, Enum):
    REST = "rest"
    API = "api"
    SSH_CLI = "ssh_cli"


@dataclass(frozen=True)
class MikroTikToolSpec:
    name: str
    routeros_path: str
    action: str
    mode: MikroTikToolMode
    preferred_transport: MikroTikTransport
    required_policies: tuple[str, ...]
    features: frozenset[str]
    documentation_url: str
    management_critical: bool = False
    continuous: bool = False

    @property
    def mutates_configuration(self) -> bool:
        return self.mode in {MikroTikToolMode.WRITE, MikroTikToolMode.DESTRUCTIVE}

    @property
    def requires_explicit_write_gate(self) -> bool:
        return self.mutates_configuration

    def as_dict(self) -> dict[str, object]:
        return {
            "name": self.name,
            "routeros_path": self.routeros_path,
            "action": self.action,
            "mode": self.mode.value,
            "preferred_transport": self.preferred_transport.value,
            "required_policies": list(self.required_policies),
            "features": sorted(self.features),
            "documentation_url": self.documentation_url,
            "management_critical": self.management_critical,
            "continuous": self.continuous,
            "mutates_configuration": self.mutates_configuration,
            "requires_explicit_write_gate": self.requires_explicit_write_gate,
        }


def _tool(name: str, path: str, action: str, mode: MikroTikToolMode,
          transport: MikroTikTransport, policies: tuple[str, ...],
          features: tuple[str, ...], docs: str, *, management_critical: bool = False,
          continuous: bool = False) -> MikroTikToolSpec:
    return MikroTikToolSpec(
        name=name,
        routeros_path=path,
        action=action,
        mode=mode,
        preferred_transport=transport,
        required_policies=policies,
        features=frozenset(features),
        documentation_url=topic_url(docs),
        management_critical=management_critical,
        continuous=continuous,
    )


_CATALOG = (
    _tool("mikrotik.inventory.system_resource", "/system/resource", "print", MikroTikToolMode.READ_ONLY, MikroTikTransport.REST, ("read", "rest-api"), ("inventory",), "rest_api"),
    _tool("mikrotik.interface.list", "/interface", "print", MikroTikToolMode.READ_ONLY, MikroTikTransport.REST, ("read", "rest-api"), ("interface", "internet", "vpn", "vlan"), "rest_api"),
    _tool("mikrotik.bridge.vlan.list", "/interface/bridge/vlan", "print", MikroTikToolMode.READ_ONLY, MikroTikTransport.REST, ("read", "rest-api"), ("bridge", "vlan"), "rest_api"),
    _tool("mikrotik.ip.address.list", "/ip/address", "print", MikroTikToolMode.READ_ONLY, MikroTikTransport.REST, ("read", "rest-api"), ("internet", "routing", "vpn", "vlan"), "rest_api"),
    _tool("mikrotik.route.list", "/ip/route", "print", MikroTikToolMode.READ_ONLY, MikroTikTransport.REST, ("read", "rest-api"), ("internet", "routing", "vpn"), "rest_api"),
    _tool("mikrotik.dhcp.client.list", "/ip/dhcp-client", "print", MikroTikToolMode.READ_ONLY, MikroTikTransport.REST, ("read", "rest-api"), ("internet",), "rest_api"),
    _tool("mikrotik.firewall.filter.list", "/ip/firewall/filter", "print", MikroTikToolMode.READ_ONLY, MikroTikTransport.REST, ("read", "rest-api"), ("firewall", "internet", "vpn", "security"), "firewall"),
    _tool("mikrotik.firewall.nat.list", "/ip/firewall/nat", "print", MikroTikToolMode.READ_ONLY, MikroTikTransport.REST, ("read", "rest-api"), ("firewall", "internet", "vpn", "security"), "firewall"),
    _tool("mikrotik.service.list", "/ip/service", "print", MikroTikToolMode.READ_ONLY, MikroTikTransport.REST, ("read", "rest-api"), ("management", "security", "internet"), "security"),
    _tool("mikrotik.wireguard.interface.list", "/interface/wireguard", "print", MikroTikToolMode.READ_ONLY, MikroTikTransport.REST, ("read", "rest-api"), ("vpn", "wireguard"), "wireguard"),
    _tool("mikrotik.wireguard.peer.list", "/interface/wireguard/peers", "print", MikroTikToolMode.READ_ONLY, MikroTikTransport.REST, ("read", "rest-api"), ("vpn", "wireguard"), "wireguard"),
    _tool("mikrotik.diag.ping", "/ping", "run", MikroTikToolMode.TEST, MikroTikTransport.REST, ("read", "test", "rest-api"), ("diagnostic", "internet", "routing", "vpn"), "rest_api"),
    _tool("mikrotik.diag.traceroute", "/tool/traceroute", "run", MikroTikToolMode.TEST, MikroTikTransport.REST, ("read", "test", "rest-api"), ("diagnostic", "internet", "routing"), "rest_api"),
    _tool("mikrotik.capture.torch", "/tool/torch", "monitor", MikroTikToolMode.CAPTURE, MikroTikTransport.API, ("read", "test", "sniff", "api"), ("capture", "diagnostic"), "api", continuous=True),
    _tool("mikrotik.config.ip.address.create", "/ip/address", "add", MikroTikToolMode.WRITE, MikroTikTransport.REST, ("read", "write", "rest-api"), ("internet", "routing", "vpn", "vlan"), "rest_api", management_critical=True),
    _tool("mikrotik.config.route.create", "/ip/route", "add", MikroTikToolMode.WRITE, MikroTikTransport.REST, ("read", "write", "rest-api"), ("internet", "routing", "vpn"), "rest_api", management_critical=True),
    _tool("mikrotik.config.firewall.filter.create", "/ip/firewall/filter", "add", MikroTikToolMode.WRITE, MikroTikTransport.REST, ("read", "write", "rest-api"), ("firewall", "internet", "vpn", "security"), "firewall", management_critical=True),
    _tool("mikrotik.config.firewall.nat.create", "/ip/firewall/nat", "add", MikroTikToolMode.WRITE, MikroTikTransport.REST, ("read", "write", "rest-api"), ("firewall", "internet", "vpn", "security"), "firewall", management_critical=True),
    _tool("mikrotik.config.wireguard.interface.create", "/interface/wireguard", "add", MikroTikToolMode.WRITE, MikroTikTransport.REST, ("read", "write", "rest-api"), ("vpn", "wireguard"), "wireguard", management_critical=True),
    _tool("mikrotik.config.wireguard.peer.create", "/interface/wireguard/peers", "add", MikroTikToolMode.WRITE, MikroTikTransport.REST, ("read", "write", "rest-api"), ("vpn", "wireguard"), "wireguard", management_critical=True),
)


def mikrotik_tool_catalog() -> tuple[MikroTikToolSpec, ...]:
    return _CATALOG


def tool_by_name(name: str) -> MikroTikToolSpec:
    for tool in _CATALOG:
        if tool.name == name:
            return tool
    raise KeyError(f"unknown MikroTik tool: {name}")


def select_tools(features: Iterable[str], *, include_writes: bool = False,
                 include_capture: bool = False) -> tuple[MikroTikToolSpec, ...]:
    requested = {str(item).strip().lower() for item in features if str(item).strip()}
    selected: list[MikroTikToolSpec] = []
    for tool in _CATALOG:
        if requested and tool.features.isdisjoint(requested):
            continue
        if tool.mode is MikroTikToolMode.CAPTURE and not include_capture:
            continue
        if tool.mutates_configuration and not include_writes:
            continue
        selected.append(tool)
    selected.sort(key=lambda item: item.name)
    return tuple(selected)


_INTENT_FEATURES: Mapping[str, tuple[str, ...]] = {
    "secure_internet_gateway": ("inventory", "interface", "internet", "routing", "firewall", "security", "diagnostic", "management"),
    "site_to_site_wireguard": ("inventory", "interface", "routing", "firewall", "security", "diagnostic", "vpn", "wireguard"),
}


def tools_for_intent(intent_kind: str, *, include_writes: bool = False,
                     include_capture: bool = False) -> tuple[MikroTikToolSpec, ...]:
    key = intent_kind.strip().lower()
    try:
        features = _INTENT_FEATURES[key]
    except KeyError as exc:
        raise KeyError(f"unknown MikroTik intent kind: {intent_kind}") from exc
    return select_tools(features, include_writes=include_writes, include_capture=include_capture)
