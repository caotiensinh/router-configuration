from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass
from enum import Enum
from types import MappingProxyType
from typing import Any, Mapping

from .docs import topic_urls
from .tool_registry import tools_for_intent


class MikroTikIntentError(ValueError):
    pass


class MikroTikIntentKind(str, Enum):
    SECURE_INTERNET_GATEWAY = "secure_internet_gateway"
    SITE_TO_SITE_WIREGUARD = "site_to_site_wireguard"


_SECRET_SCHEMES = ("env://", "vault://", "keyring://")
_SITE_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,62}$")
_ADDRESSING = {"dhcp", "static", "pppoe", "isp_defined"}


@dataclass(frozen=True)
class MikroTikIntentPlan:
    kind: MikroTikIntentKind
    facts: Mapping[str, Any]
    derived_policy: Mapping[str, Any]
    required_discovery: tuple[str, ...]
    tool_names: tuple[str, ...]
    verification: tuple[str, ...]
    documentation_urls: tuple[str, ...]
    blockers: tuple[str, ...] = ()
    secret_references: tuple[str, ...] = ()

    @property
    def ready_for_planning(self) -> bool:
        return not self.blockers

    @property
    def write_authorized(self) -> bool:
        return False

    def as_dict(self) -> dict[str, Any]:
        return {
            "schema_version": "mikrotik-operator-intent/1",
            "kind": self.kind.value,
            "facts": dict(self.facts),
            "derived_policy": dict(self.derived_policy),
            "required_discovery": list(self.required_discovery),
            "tool_names": list(self.tool_names),
            "verification": list(self.verification),
            "documentation_urls": list(self.documentation_urls),
            "blockers": list(self.blockers),
            "secret_references": list(self.secret_references),
            "ready_for_planning": self.ready_for_planning,
            "write_authorized": False,
            "vendor_commands_present": False,
            "transport_present": False,
        }


def _network(value: Any, label: str) -> ipaddress.IPv4Network:
    text = str(value or "").strip()
    try:
        network = ipaddress.ip_network(text, strict=False)
    except ValueError as exc:
        raise MikroTikIntentError(f"{label} must be an IPv4 CIDR") from exc
    if network.version != 4 or network.prefixlen == 0:
        raise MikroTikIntentError(f"{label} must be a bounded IPv4 CIDR")
    if network.is_multicast or network.is_loopback or network.is_unspecified:
        raise MikroTikIntentError(f"{label} must describe a usable IPv4 network")
    return network


def _interface(value: Any, label: str) -> str:
    text = str(value or "").strip()
    if not text:
        raise MikroTikIntentError(f"{label} is required")
    if any(char in text for char in "\r\n;"):
        raise MikroTikIntentError(f"{label} contains unsupported characters")
    return text


def _site_id(value: Any, label: str) -> str:
    text = str(value or "").strip()
    if not _SITE_ID.fullmatch(text):
        raise MikroTikIntentError(f"{label} contains unsupported characters")
    return text


def _secret_reference(value: Any, label: str) -> str | None:
    if value is None:
        return None
    text = str(value).strip()
    if not text.startswith(_SECRET_SCHEMES):
        raise MikroTikIntentError(
            f"{label} must be a secret reference using env://, vault://, or keyring://"
        )
    return text


def _tool_names(intent_kind: MikroTikIntentKind) -> tuple[str, ...]:
    return tuple(tool.name for tool in tools_for_intent(intent_kind.value))


def _freeze(data: Mapping[str, Any]) -> Mapping[str, Any]:
    return MappingProxyType(dict(data))


def compile_secure_internet_gateway(request: Mapping[str, Any]) -> MikroTikIntentPlan:
    lan = _network(request.get("lan_cidr"), "lan_cidr")
    lan_interface = _interface(request.get("lan_interface"), "lan_interface")
    wan_interface = _interface(request.get("wan_interface"), "wan_interface")
    if lan_interface == wan_interface:
        raise MikroTikIntentError("LAN and WAN interfaces must be different")

    addressing = str(request.get("wan_addressing") or "dhcp").strip().lower()
    if addressing not in _ADDRESSING:
        raise MikroTikIntentError(
            "wan_addressing must be one of: " + ", ".join(sorted(_ADDRESSING))
        )

    credential_ref = _secret_reference(request.get("credential_ref"), "credential_ref")
    facts = {
        "lan_cidr": str(lan),
        "lan_interface": lan_interface,
        "wan_interface": wan_interface,
        "wan_addressing": addressing,
    }

    blockers: list[str] = []
    if addressing == "static":
        if not str(request.get("wan_address") or "").strip():
            blockers.append("static WAN requires wan_address")
        if not str(request.get("wan_gateway") or "").strip():
            blockers.append("static WAN requires wan_gateway")

    derived_policy = {
        "goal": "LAN can initiate IPv4 Internet access while WAN-initiated access is denied by default",
        "lan_to_internet": "allow",
        "wan_to_lan_unsolicited": "deny",
        "wan_to_router_management": "deny",
        "wan_echo_request": "deny",
        "icmp_control_errors": "preserve_required_ipv4_control_messages",
        "connection_tracking": "accept_established_related_drop_invalid",
        "ipv4_source_nat": "required_when_discovery_confirms_private_LAN_to_public_WAN",
        "management_sources": [str(lan)],
        "management_services": "LAN_only",
        "port_scan_policy": "default_deny_is_primary_control; detection/logging is optional",
        "configuration_strategy": "desired_state_diff_idempotent",
        "rollback_required": True,
        "verify_after_each_management_critical_step": True,
    }
    required_discovery = (
        "system_resource_and_routeros_version",
        "interfaces_and_link_state",
        "existing_ip_addresses",
        "wan_addressing_state",
        "default_routes_and_routing_tables",
        "firewall_filter_rules",
        "firewall_nat_rules",
        "ip_services_and_management_exposure",
        "current_management_path",
    )
    verification = (
        "management_path_survives",
        "LAN_gateway_reachable",
        "LAN_can_reach_public_IP",
        "required_DNS_resolution_works_when_DNS_is_in_scope",
        "WAN_cannot_initiate_new_forward_to_LAN",
        "WAN_management_is_not_exposed",
        "WAN_echo_request_policy_matches_intent",
        "desired_state_is_idempotent_on_second_plan",
    )
    references = (credential_ref,) if credential_ref else ()
    return MikroTikIntentPlan(
        kind=MikroTikIntentKind.SECURE_INTERNET_GATEWAY,
        facts=_freeze(facts),
        derived_policy=_freeze(derived_policy),
        required_discovery=required_discovery,
        tool_names=_tool_names(MikroTikIntentKind.SECURE_INTERNET_GATEWAY),
        verification=verification,
        documentation_urls=topic_urls(
            ("rest_api", "firewall", "security", "configuration_management")
        ),
        blockers=tuple(blockers),
        secret_references=references,
    )


def compile_site_to_site_wireguard(request: Mapping[str, Any]) -> MikroTikIntentPlan:
    local_site = _site_id(request.get("local_site_id"), "local_site_id")
    remote_site = _site_id(request.get("remote_site_id"), "remote_site_id")
    if local_site == remote_site:
        raise MikroTikIntentError("local_site_id and remote_site_id must differ")

    local_lan = _network(request.get("local_lan_cidr"), "local_lan_cidr")
    remote_lan = _network(request.get("remote_lan_cidr"), "remote_lan_cidr")
    if local_lan.overlaps(remote_lan):
        raise MikroTikIntentError(
            "site-to-site LANs overlap; automatic routing must stop for explicit conflict resolution"
        )

    local_credential = _secret_reference(
        request.get("local_credential_ref"), "local_credential_ref"
    )
    remote_credential = _secret_reference(
        request.get("remote_credential_ref"), "remote_credential_ref"
    )
    secret_refs = tuple(
        item for item in (local_credential, remote_credential) if item is not None
    )

    facts = {
        "local_site_id": local_site,
        "remote_site_id": remote_site,
        "local_lan_cidr": str(local_lan),
        "remote_lan_cidr": str(remote_lan),
        "vpn_type": "wireguard",
    }
    derived_policy = {
        "goal": "route only the two declared LANs through an encrypted site-to-site tunnel",
        "key_management": "generate_unique_keypair_per_site_and_store_as_secret_reference",
        "tunnel_addressing": "allocate_non_overlapping_/30_after_both_sites_are_discovered",
        "allowed_addresses": "remote_tunnel_host_and_remote_LAN_only",
        "default_route_over_vpn": False,
        "internet_breakout": "local_at_each_site",
        "forward_policy": "allow_declared_LAN_to_declared_LAN_only",
        "wireguard_input": "allow_only_required_UDP_listener_before_default_deny",
        "persistent_keepalive": "enable_only_when_NAT_or_firewall_state_requires_it",
        "nat_handling": "derive_after_discovery; avoid_accidental_masquerade_between_declared_LANs",
        "configuration_strategy": "desired_state_diff_idempotent",
        "rollback_required": True,
        "verify_after_each_management_critical_step": True,
    }
    required_discovery = (
        "routeros_version_and_wireguard_capability_on_both_sites",
        "interfaces_and_management_path_on_both_sites",
        "WAN_addresses_routes_and_NAT_reachability_on_both_sites",
        "existing_WireGuard_interfaces_and_peers",
        "existing_routes_and_routing_tables",
        "firewall_input_and_forward_rules",
        "firewall_NAT_rules",
        "subnet_overlap_check_across_both_sites",
    )
    verification = (
        "management_path_survives_on_both_sites",
        "WireGuard_handshake_is_recent",
        "tunnel_peer_address_reachable",
        "local_LAN_reaches_remote_LAN",
        "remote_LAN_reaches_local_LAN",
        "Internet_default_route_remains_local_on_both_sites",
        "undeclared_VPN_forwarding_is_denied",
        "desired_state_is_idempotent_on_second_plan",
    )
    return MikroTikIntentPlan(
        kind=MikroTikIntentKind.SITE_TO_SITE_WIREGUARD,
        facts=_freeze(facts),
        derived_policy=_freeze(derived_policy),
        required_discovery=required_discovery,
        tool_names=_tool_names(MikroTikIntentKind.SITE_TO_SITE_WIREGUARD),
        verification=verification,
        documentation_urls=topic_urls(
            ("rest_api", "wireguard", "firewall", "configuration_management")
        ),
        secret_references=secret_refs,
    )


def compile_mikrotik_operator_intent(request: Mapping[str, Any]) -> MikroTikIntentPlan:
    kind = str(request.get("kind") or "").strip().lower()
    if kind == MikroTikIntentKind.SECURE_INTERNET_GATEWAY.value:
        return compile_secure_internet_gateway(request)
    if kind == MikroTikIntentKind.SITE_TO_SITE_WIREGUARD.value:
        return compile_site_to_site_wireguard(request)
    raise MikroTikIntentError(
        "kind must be secure_internet_gateway or site_to_site_wireguard"
    )
