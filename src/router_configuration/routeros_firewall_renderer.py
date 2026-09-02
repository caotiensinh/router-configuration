from __future__ import annotations

import hashlib
import ipaddress
import json
from dataclasses import dataclass
from typing import Any, Mapping


class RouterOSFirewallRenderError(ValueError):
    pass


WAN_INTERFACE_LIST = "routercfg-WAN"
CORE_INTERFACE_LIST = "routercfg-CORE"
MANAGEMENT_ADDRESS_LIST = "routercfg-MGMT-SOURCES"
INPUT_CHAIN = "routercfg-input"
STAGING_GUARD_COMMENT = "routercfg:managed:fw-stage-guard"
INPUT_JUMP_COMMENT = "routercfg:managed:fw:input-jump"
ADDRESS_COMMENT_PREFIX = "routercfg:managed:fw:addr:"
CHAIN_COMMENT_PREFIX = "routercfg:managed:fw:chain:"


def _quote(value: str) -> str:
    return '"' + value.replace("\\", "\\\\").replace('"', '\\"').replace("$", "\\$") + '"'


def _canonical_sha256(payload: Mapping[str, Any]) -> str:
    canonical = json.dumps(
        payload,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        default=str,
    ).encode("utf-8")
    return hashlib.sha256(canonical).hexdigest()


def _verify_ir(ir: Mapping[str, Any]) -> None:
    if ir.get("schema_version") != "config-safe-subset-ir/1":
        raise RouterOSFirewallRenderError("unsupported safe-subset IR schema")
    if ir.get("vendor_commands_present") is not False:
        raise RouterOSFirewallRenderError("firewall renderer requires command-free safe-subset IR")
    if ir.get("write_transport_present") is not False:
        raise RouterOSFirewallRenderError("firewall renderer refuses IR containing a write transport")
    supplied = str(ir.get("ir_sha256") or "").strip()
    if not supplied:
        raise RouterOSFirewallRenderError("safe-subset IR is missing ir_sha256")
    unsigned = dict(ir)
    unsigned.pop("ir_sha256", None)
    if supplied != _canonical_sha256(unsigned):
        raise RouterOSFirewallRenderError("safe-subset IR digest mismatch")


def _bounded_ipv4_network(value: Any, label: str) -> str:
    text = str(value or "").strip()
    try:
        network = ipaddress.ip_network(text, strict=False)
    except ValueError as exc:
        raise RouterOSFirewallRenderError(f"{label} must be an IPv4 CIDR") from exc
    if network.version != 4 or network.prefixlen == 0:
        raise RouterOSFirewallRenderError(f"{label} must be a bounded IPv4 CIDR")
    return str(network)


@dataclass(frozen=True)
class RouterOSFirewallCommand:
    command_id: str
    section: str
    command: str
    risk: int = 30

    def as_dict(self) -> dict[str, Any]:
        return {
            "command_id": self.command_id,
            "section": self.section,
            "command": self.command,
            "risk": self.risk,
        }


@dataclass(frozen=True)
class RouterOSFirewallCommandPlan:
    commands: tuple[RouterOSFirewallCommand, ...]
    management_sources: tuple[str, ...]
    required_wan_services: tuple[Mapping[str, Any], ...]

    def as_dict(self) -> dict[str, Any]:
        return {
            "schema_version": "routeros-firewall-command-plan/1",
            "scope": "generation_only",
            "policy": "enterprise_baseline_ipv4_input_v0.1",
            "managed_chain": INPUT_CHAIN,
            "required_interface_lists": [WAN_INTERFACE_LIST, CORE_INTERFACE_LIST],
            "management_sources": list(self.management_sources),
            "required_wan_services": [dict(item) for item in self.required_wan_services],
            "anti_spoofing_scope": "reject WAN packets claiming configured management-source CIDRs",
            "commands": [command.as_dict() for command in self.commands],
            "command_count": len(self.commands),
            "transport_present": False,
            "apply_available": False,
            "write_authorized": False,
        }


def _firewall_attributes(ir: Mapping[str, Any]) -> Mapping[str, Any]:
    operations = ir.get("operations", [])
    if not isinstance(operations, list):
        raise RouterOSFirewallRenderError("safe-subset IR operations must be a list")
    candidates = [
        item
        for item in operations
        if isinstance(item, Mapping) and str(item.get("resource") or "") == "firewall_baseline"
    ]
    if len(candidates) != 1:
        raise RouterOSFirewallRenderError("firewall renderer requires exactly one firewall_baseline operation")
    attributes = candidates[0].get("attributes", {})
    if not isinstance(attributes, Mapping):
        raise RouterOSFirewallRenderError("firewall_baseline attributes must be an object")
    return attributes


def _require_topology_lists(ir: Mapping[str, Any]) -> None:
    operations = ir.get("operations", [])
    assert isinstance(operations, list)
    wan_count = sum(
        1
        for item in operations
        if isinstance(item, Mapping) and str(item.get("resource") or "") == "wan_role"
    )
    core_count = sum(
        1
        for item in operations
        if isinstance(item, Mapping) and str(item.get("resource") or "") == "core_uplink_role"
    )
    if wan_count < 1 or core_count != 1:
        raise RouterOSFirewallRenderError(
            "enterprise firewall rendering requires at least one WAN role and exactly one core uplink role"
        )


def _management_sources(attributes: Mapping[str, Any]) -> tuple[str, ...]:
    if "management_sources" not in attributes:
        raise RouterOSFirewallRenderError("security.management_sources must be explicit before firewall rendering")
    raw = attributes.get("management_sources")
    if not isinstance(raw, list) or not raw:
        raise RouterOSFirewallRenderError("security.management_sources requires at least one bounded CIDR")
    normalized = tuple(sorted({_bounded_ipv4_network(value, "security.management_sources") for value in raw}))
    if not normalized:
        raise RouterOSFirewallRenderError("security.management_sources requires at least one bounded CIDR")
    return normalized


def _required_wan_services(attributes: Mapping[str, Any]) -> tuple[Mapping[str, Any], ...]:
    if "required_wan_services" not in attributes:
        raise RouterOSFirewallRenderError(
            "security.required_wan_services must be explicit, using [] when no WAN service is required"
        )
    raw = attributes.get("required_wan_services")
    if not isinstance(raw, list):
        raise RouterOSFirewallRenderError("security.required_wan_services must be a list")

    normalized: list[Mapping[str, Any]] = []
    seen: set[tuple[str, int, tuple[str, ...]]] = set()
    for index, item in enumerate(raw):
        if not isinstance(item, Mapping):
            raise RouterOSFirewallRenderError(f"security.required_wan_services[{index}] must be an object")
        name = str(item.get("name") or "").strip()
        protocol = str(item.get("protocol") or "").strip().lower()
        dst_port = item.get("dst_port")
        sources_raw = item.get("source_cidrs")
        if not name:
            raise RouterOSFirewallRenderError(f"security.required_wan_services[{index}].name is required")
        if protocol not in {"tcp", "udp"}:
            raise RouterOSFirewallRenderError(
                f"security.required_wan_services[{index}].protocol must be tcp or udp"
            )
        if isinstance(dst_port, bool) or not isinstance(dst_port, int) or not 1 <= dst_port <= 65535:
            raise RouterOSFirewallRenderError(
                f"security.required_wan_services[{index}].dst_port must be an integer from 1 to 65535"
            )
        if not isinstance(sources_raw, list) or not sources_raw:
            raise RouterOSFirewallRenderError(
                f"security.required_wan_services[{index}].source_cidrs requires at least one bounded CIDR"
            )
        sources = tuple(
            sorted(
                {
                    _bounded_ipv4_network(
                        value,
                        f"security.required_wan_services[{index}].source_cidrs",
                    )
                    for value in sources_raw
                }
            )
        )
        key = (protocol, dst_port, sources)
        if key in seen:
            raise RouterOSFirewallRenderError("security.required_wan_services contains a duplicate service rule")
        seen.add(key)
        normalized.append(
            {
                "name": name,
                "protocol": protocol,
                "dst_port": dst_port,
                "source_cidrs": list(sources),
            }
        )
    normalized.sort(key=lambda item: (str(item["protocol"]), int(item["dst_port"]), str(item["name"])))
    return tuple(normalized)


def _validate_baseline(attributes: Mapping[str, Any]) -> None:
    if str(attributes.get("profile") or "") != "enterprise_baseline":
        raise RouterOSFirewallRenderError("firewall renderer supports only enterprise_baseline")
    if str(attributes.get("wan_input_default") or "") != "deny":
        raise RouterOSFirewallRenderError("enterprise firewall requires wan_input_default=deny")
    if attributes.get("management_from_wan") is not False:
        raise RouterOSFirewallRenderError("enterprise firewall refuses management_from_wan")
    if attributes.get("anti_spoofing") is not True:
        raise RouterOSFirewallRenderError("enterprise firewall requires anti_spoofing=true")
    if str(attributes.get("icmp_policy") or "") != "essential_ipv4":
        raise RouterOSFirewallRenderError("enterprise firewall requires icmp_policy=essential_ipv4")


def _command(command_id: str, section: str, command: str) -> RouterOSFirewallCommand:
    return RouterOSFirewallCommand(command_id=command_id, section=section, command=command)


def render_routeros_firewall(*, ir: Mapping[str, Any]) -> RouterOSFirewallCommandPlan:
    """Render a strict IPv4 router-input baseline without any write transport.

    The plan uses a temporary fail-closed input guard, rebuilds a reserved custom
    chain, inserts a jump before the guard, then removes the guard. This keeps
    ordering deterministic without relying on unstable item numbers. The output
    is still generation-only; no production apply path exists here.
    """

    _verify_ir(ir)
    _require_topology_lists(ir)
    attributes = _firewall_attributes(ir)
    _validate_baseline(attributes)
    management_sources = _management_sources(attributes)
    services = _required_wan_services(attributes)

    commands: list[RouterOSFirewallCommand] = []

    guard_q = _quote(STAGING_GUARD_COMMENT)
    commands.append(
        _command(
            "firewall.00.stage-guard",
            "firewall_filter",
            (
                f"/ip/firewall/filter/remove [find where comment={guard_q}]; "
                ':local first [:pick [/ip/firewall/filter/find where chain=input] 0]; '
                f':if ([:len $first] = 0) do={{/ip/firewall/filter/add chain=input action=drop comment={guard_q}}} '
                f'else={{/ip/firewall/filter/add chain=input action=drop comment={guard_q} place-before=$first}}'
            ),
        )
    )
    commands.append(
        _command(
            "firewall.01.cleanup-chain",
            "firewall_filter",
            f'/ip/firewall/filter/remove [find where chain={_quote(INPUT_CHAIN)}]',
        )
    )
    commands.append(
        _command(
            "firewall.02.cleanup-address-lists",
            "firewall_address_list",
            f'/ip/firewall/address-list/remove [find where comment~{_quote("^" + ADDRESS_COMMENT_PREFIX)}]',
        )
    )

    for index, source in enumerate(management_sources, start=1):
        commands.append(
            _command(
                f"firewall.10.management-source.{index:03d}",
                "firewall_address_list",
                (
                    f'/ip/firewall/address-list/add list={_quote(MANAGEMENT_ADDRESS_LIST)} '
                    f'address={_quote(source)} comment={_quote(ADDRESS_COMMENT_PREFIX + f"mgmt:{index:03d}")}'
                ),
            )
        )

    for service_index, service in enumerate(services, start=1):
        list_name = f"routercfg-WAN-SVC-{service_index:03d}"
        for source_index, source in enumerate(service["source_cidrs"], start=1):
            commands.append(
                _command(
                    f"firewall.20.wan-service-source.{service_index:03d}.{source_index:03d}",
                    "firewall_address_list",
                    (
                        f'/ip/firewall/address-list/add list={_quote(list_name)} address={_quote(str(source))} '
                        f'comment={_quote(ADDRESS_COMMENT_PREFIX + f"service:{service_index:03d}:{source_index:03d}")}'
                    ),
                )
            )

    chain_q = _quote(INPUT_CHAIN)
    commands.extend(
        (
            _command(
                "firewall.30.rule.010-established-related",
                "firewall_filter",
                f'/ip/firewall/filter/add chain={chain_q} action=accept connection-state=established,related comment={_quote(CHAIN_COMMENT_PREFIX + "010-established-related")}',
            ),
            _command(
                "firewall.30.rule.020-invalid-drop",
                "firewall_filter",
                f'/ip/firewall/filter/add chain={chain_q} action=drop connection-state=invalid comment={_quote(CHAIN_COMMENT_PREFIX + "020-invalid-drop")}',
            ),
            _command(
                "firewall.30.rule.030-icmp",
                "firewall_filter",
                f'/ip/firewall/filter/add chain={chain_q} action=accept protocol=icmp comment={_quote(CHAIN_COMMENT_PREFIX + "030-essential-icmp")}',
            ),
            _command(
                "firewall.30.rule.040-management-antispoof",
                "firewall_filter",
                (
                    f'/ip/firewall/filter/add chain={chain_q} action=drop '
                    f'in-interface-list={_quote(WAN_INTERFACE_LIST)} src-address-list={_quote(MANAGEMENT_ADDRESS_LIST)} '
                    f'comment={_quote(CHAIN_COMMENT_PREFIX + "040-management-antispoof")}'
                ),
            ),
            _command(
                "firewall.30.rule.050-management-accept",
                "firewall_filter",
                (
                    f'/ip/firewall/filter/add chain={chain_q} action=accept connection-state=new '
                    f'in-interface-list={_quote(CORE_INTERFACE_LIST)} src-address-list={_quote(MANAGEMENT_ADDRESS_LIST)} '
                    f'comment={_quote(CHAIN_COMMENT_PREFIX + "050-management-accept")}'
                ),
            ),
        )
    )

    for service_index, service in enumerate(services, start=1):
        list_name = f"routercfg-WAN-SVC-{service_index:03d}"
        commands.append(
            _command(
                f"firewall.30.rule.060-wan-service.{service_index:03d}",
                "firewall_filter",
                (
                    f'/ip/firewall/filter/add chain={chain_q} action=accept connection-state=new '
                    f'in-interface-list={_quote(WAN_INTERFACE_LIST)} protocol={service["protocol"]} '
                    f'dst-port={int(service["dst_port"])} src-address-list={_quote(list_name)} '
                    f'comment={_quote(CHAIN_COMMENT_PREFIX + f"060-wan-service:{service_index:03d}")}'
                ),
            )
        )

    commands.extend(
        (
            _command(
                "firewall.30.rule.090-wan-default-deny",
                "firewall_filter",
                f'/ip/firewall/filter/add chain={chain_q} action=drop in-interface-list={_quote(WAN_INTERFACE_LIST)} comment={_quote(CHAIN_COMMENT_PREFIX + "090-wan-default-deny")}',
            ),
            _command(
                "firewall.30.rule.099-input-default-deny",
                "firewall_filter",
                f'/ip/firewall/filter/add chain={chain_q} action=drop comment={_quote(CHAIN_COMMENT_PREFIX + "099-input-default-deny")}',
            ),
        )
    )

    jump_q = _quote(INPUT_JUMP_COMMENT)
    commands.append(
        _command(
            "firewall.90.activate-chain",
            "firewall_filter",
            (
                f':local guard [/ip/firewall/filter/find where comment={guard_q}]; '
                ':if ([:len $guard] != 1) do={:error "routercfg firewall staging guard missing"}; '
                f'/ip/firewall/filter/remove [find where comment={jump_q}]; '
                f'/ip/firewall/filter/add chain=input action=jump jump-target={chain_q} comment={jump_q} place-before=$guard'
            ),
        )
    )
    commands.append(
        _command(
            "firewall.99.remove-stage-guard",
            "firewall_filter",
            f'/ip/firewall/filter/remove [find where comment={guard_q}]',
        )
    )

    commands.sort(key=lambda item: item.command_id)
    return RouterOSFirewallCommandPlan(
        commands=tuple(commands),
        management_sources=management_sources,
        required_wan_services=services,
    )
