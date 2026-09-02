from __future__ import annotations

import base64
import binascii
import ipaddress
import re
from dataclasses import dataclass
from typing import Any, Mapping


class WireGuardIntentError(ValueError):
    pass


_NAME = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,30}$")
_HOST = re.compile(r"^[A-Za-z0-9][A-Za-z0-9.-]{0,252}[A-Za-z0-9]$|^[A-Za-z0-9]$")


def _name(value: Any, label: str) -> str:
    text = str(value or "").strip()
    if not _NAME.fullmatch(text):
        raise WireGuardIntentError(f"{label} contains unsupported characters")
    return text


def _port(value: Any, label: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or not 1 <= value <= 65535:
        raise WireGuardIntentError(f"{label} must be an integer from 1 to 65535")
    return value


def _interface(value: Any, label: str) -> ipaddress.IPv4Interface:
    try:
        interface = ipaddress.ip_interface(str(value or "").strip())
    except ValueError as exc:
        raise WireGuardIntentError(f"{label} must be an IPv4 interface CIDR") from exc
    if interface.version != 4 or interface.network.prefixlen == 0:
        raise WireGuardIntentError(f"{label} must be a bounded IPv4 interface CIDR")
    if interface.ip.is_unspecified or interface.ip.is_multicast or interface.ip.is_loopback:
        raise WireGuardIntentError(f"{label} must use a usable unicast IPv4 address")
    return interface


def _network(value: Any, label: str, *, host: bool = False) -> ipaddress.IPv4Network:
    try:
        network = ipaddress.ip_network(str(value or "").strip(), strict=False)
    except ValueError as exc:
        raise WireGuardIntentError(f"{label} must be an IPv4 CIDR") from exc
    if network.version != 4 or network.prefixlen == 0:
        raise WireGuardIntentError(f"{label} must be a bounded IPv4 CIDR")
    if host and network.prefixlen != 32:
        raise WireGuardIntentError(f"{label} must be an IPv4 /32")
    return network


def _public_key(value: Any, label: str) -> str:
    text = str(value or "").strip()
    try:
        decoded = base64.b64decode(text, validate=True)
    except (binascii.Error, ValueError) as exc:
        raise WireGuardIntentError(f"{label} must be base64") from exc
    if len(decoded) != 32:
        raise WireGuardIntentError(f"{label} must decode to exactly 32 bytes")
    return text


def _endpoint(value: Any, label: str) -> str:
    text = str(value or "").strip()
    if not text:
        raise WireGuardIntentError(f"{label} must not be empty")
    try:
        address = ipaddress.ip_address(text)
    except ValueError:
        if not _HOST.fullmatch(text) or ".." in text:
            raise WireGuardIntentError(f"{label} must be an IP address or conservative DNS name")
    else:
        if address.is_unspecified or address.is_multicast:
            raise WireGuardIntentError(f"{label} must be a usable endpoint")
    return text


@dataclass(frozen=True)
class NormalizedWireGuardIntent:
    attributes: Mapping[str, Any]
    secret_ref: str


def normalize_wireguard_intent(wireguard: Mapping[str, Any]) -> NormalizedWireGuardIntent:
    if wireguard.get("enabled") is not True:
        raise WireGuardIntentError("WireGuard intent requires enabled=true")

    secret_ref = str(wireguard.get("secret_ref") or "").strip()
    if not secret_ref.startswith(("env://", "vault://", "keyring://")):
        raise WireGuardIntentError("WireGuard intent requires an unresolved secret reference")

    name = _name(wireguard.get("name"), "wireguard.name")
    listen_port = _port(wireguard.get("listen_port"), "wireguard.listen_port")
    mtu = wireguard.get("mtu")
    if isinstance(mtu, bool) or not isinstance(mtu, int) or not 1280 <= mtu <= 1500:
        raise WireGuardIntentError("wireguard.mtu must be an integer from 1280 to 1500")

    raw_addresses = wireguard.get("addresses")
    if not isinstance(raw_addresses, list) or not raw_addresses:
        raise WireGuardIntentError("wireguard.addresses requires at least one explicit IPv4 interface CIDR")
    addresses = tuple(sorted({_interface(value, "wireguard.addresses").with_prefixlen for value in raw_addresses}))
    interface_networks = tuple(ipaddress.ip_interface(value).network for value in addresses)
    local_ips = {ipaddress.ip_interface(value).ip for value in addresses}

    raw_peers = wireguard.get("peers")
    if not isinstance(raw_peers, list) or not raw_peers:
        raise WireGuardIntentError("wireguard.peers requires at least one explicit peer")

    peer_names: set[str] = set()
    claimed_allowed: list[tuple[str, ipaddress.IPv4Network]] = []
    peers: list[dict[str, Any]] = []
    for index, raw in enumerate(raw_peers):
        if not isinstance(raw, Mapping):
            raise WireGuardIntentError(f"wireguard.peers[{index}] must be an object")
        peer_name = _name(raw.get("name"), f"wireguard.peers[{index}].name")
        if peer_name in peer_names:
            raise WireGuardIntentError("wireguard peer names must be unique")
        peer_names.add(peer_name)
        public_key = _public_key(raw.get("public_key"), f"wireguard.peers[{index}].public_key")
        tunnel = _network(raw.get("tunnel_address"), f"wireguard.peers[{index}].tunnel_address", host=True)
        tunnel_ip = tunnel.network_address
        if tunnel_ip in local_ips or not any(tunnel_ip in network for network in interface_networks):
            raise WireGuardIntentError(
                f"wireguard.peers[{index}].tunnel_address must be a remote /32 inside a configured WireGuard interface subnet"
            )

        raw_allowed = raw.get("allowed_addresses")
        if not isinstance(raw_allowed, list) or not raw_allowed:
            raise WireGuardIntentError(f"wireguard.peers[{index}].allowed_addresses must be a non-empty list")
        allowed = tuple(sorted({str(_network(value, f"wireguard.peers[{index}].allowed_addresses")) for value in raw_allowed}))
        if str(tunnel) not in allowed:
            raise WireGuardIntentError(
                f"wireguard.peers[{index}].allowed_addresses must include the explicit tunnel_address /32"
            )
        for cidr in allowed:
            network = ipaddress.ip_network(cidr)
            for previous_name, previous in claimed_allowed:
                if network.overlaps(previous):
                    raise WireGuardIntentError(
                        f"WireGuard allowed-address ranges overlap between peers {previous_name!r} and {peer_name!r}"
                    )
            claimed_allowed.append((peer_name, network))

        raw_routes = raw.get("routes", [])
        if not isinstance(raw_routes, list):
            raise WireGuardIntentError(f"wireguard.peers[{index}].routes must be a list")
        routes = tuple(sorted({str(_network(value, f"wireguard.peers[{index}].routes")) for value in raw_routes}))
        allowed_networks = [ipaddress.ip_network(value) for value in allowed]
        for route in routes:
            route_network = ipaddress.ip_network(route)
            if not any(route_network.subnet_of(candidate) for candidate in allowed_networks):
                raise WireGuardIntentError(
                    f"wireguard.peers[{index}].routes must be contained by that peer's allowed_addresses"
                )

        peer: dict[str, Any] = {
            "name": peer_name,
            "public_key": public_key,
            "tunnel_address": str(tunnel),
            "allowed_addresses": list(allowed),
            "routes": list(routes),
        }
        endpoint_address = raw.get("endpoint_address")
        endpoint_port = raw.get("endpoint_port")
        if endpoint_address is not None or endpoint_port is not None:
            peer["endpoint_address"] = _endpoint(
                endpoint_address,
                f"wireguard.peers[{index}].endpoint_address",
            )
            peer["endpoint_port"] = _port(
                endpoint_port,
                f"wireguard.peers[{index}].endpoint_port",
            )
        keepalive = raw.get("persistent_keepalive", 0)
        if isinstance(keepalive, bool) or not isinstance(keepalive, int) or not 0 <= keepalive <= 65535:
            raise WireGuardIntentError(
                f"wireguard.peers[{index}].persistent_keepalive must be an integer from 0 to 65535"
            )
        responder = raw.get("responder", False)
        if not isinstance(responder, bool):
            raise WireGuardIntentError(f"wireguard.peers[{index}].responder must be boolean")
        peer["persistent_keepalive"] = keepalive
        peer["responder"] = responder
        peers.append(peer)

    peers.sort(key=lambda item: str(item["name"]))
    return NormalizedWireGuardIntent(
        attributes={
            "enabled": True,
            "name": name,
            "addresses": list(addresses),
            "listen_port": listen_port,
            "mtu": mtu,
            "peers": peers,
        },
        secret_ref=secret_ref,
    )
