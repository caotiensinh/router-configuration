from __future__ import annotations

import base64
import binascii
import hashlib
import ipaddress
import json
import re
from dataclasses import dataclass
from typing import Any, Mapping


class RouterOSWireGuardRenderError(ValueError):
    pass


WIREGUARD_OPERATION_ID = "vpn.wireguard"
PRIVATE_KEY_PLACEHOLDER = "__ROUTERCFG_WG_PRIVATE_KEY__"
_NAME = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,30}$")
_HOST = re.compile(r"^[A-Za-z0-9][A-Za-z0-9.-]{0,252}[A-Za-z0-9]$|^[A-Za-z0-9]$")


def _quote(value: str) -> str:
    return '"' + value.replace("\\", "\\\\").replace('"', '\\"').replace("$", "\\$") + '"'


def _canonical_sha256(payload: Mapping[str, Any]) -> str:
    return hashlib.sha256(
        json.dumps(
            payload,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=False,
            default=str,
        ).encode("utf-8")
    ).hexdigest()


def _verify_ir(ir: Mapping[str, Any]) -> None:
    if ir.get("schema_version") != "config-safe-subset-ir/1":
        raise RouterOSWireGuardRenderError("unsupported safe-subset IR schema")
    if ir.get("vendor_commands_present") is not False:
        raise RouterOSWireGuardRenderError("WireGuard renderer requires command-free safe-subset IR")
    if ir.get("write_transport_present") is not False:
        raise RouterOSWireGuardRenderError("WireGuard renderer refuses IR containing a write transport")
    supplied = str(ir.get("ir_sha256") or "").strip()
    if not supplied:
        raise RouterOSWireGuardRenderError("safe-subset IR is missing ir_sha256")
    unsigned = dict(ir)
    unsigned.pop("ir_sha256", None)
    if supplied != _canonical_sha256(unsigned):
        raise RouterOSWireGuardRenderError("safe-subset IR digest mismatch")


def _operation(ir: Mapping[str, Any]) -> Mapping[str, Any]:
    operations = ir.get("operations", [])
    if not isinstance(operations, list):
        raise RouterOSWireGuardRenderError("safe-subset IR operations must be a list")
    matches = [
        item
        for item in operations
        if isinstance(item, Mapping)
        and str(item.get("operation_id") or "") == WIREGUARD_OPERATION_ID
        and str(item.get("resource") or "") == "wireguard_policy"
    ]
    if len(matches) != 1:
        raise RouterOSWireGuardRenderError("WireGuard renderer requires exactly one vpn.wireguard operation")
    return matches[0]


def _name(value: Any, label: str) -> str:
    text = str(value or "").strip()
    if not _NAME.fullmatch(text):
        raise RouterOSWireGuardRenderError(f"{label} contains unsupported characters")
    return text


def _port(value: Any, label: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or not 1 <= value <= 65535:
        raise RouterOSWireGuardRenderError(f"{label} must be an integer from 1 to 65535")
    return value


def _ipv4_interface(value: Any, label: str) -> ipaddress.IPv4Interface:
    try:
        interface = ipaddress.ip_interface(str(value or "").strip())
    except ValueError as exc:
        raise RouterOSWireGuardRenderError(f"{label} must be an IPv4 interface CIDR") from exc
    if interface.version != 4 or interface.network.prefixlen == 0:
        raise RouterOSWireGuardRenderError(f"{label} must be a bounded IPv4 interface CIDR")
    if interface.ip.is_unspecified or interface.ip.is_multicast or interface.ip.is_loopback:
        raise RouterOSWireGuardRenderError(f"{label} must use a usable unicast IPv4 address")
    return interface


def _ipv4_network(value: Any, label: str, *, require_host: bool = False) -> ipaddress.IPv4Network:
    try:
        network = ipaddress.ip_network(str(value or "").strip(), strict=False)
    except ValueError as exc:
        raise RouterOSWireGuardRenderError(f"{label} must be an IPv4 CIDR") from exc
    if network.version != 4 or network.prefixlen == 0:
        raise RouterOSWireGuardRenderError(f"{label} must be a bounded IPv4 CIDR")
    if require_host and network.prefixlen != 32:
        raise RouterOSWireGuardRenderError(f"{label} must be an IPv4 /32")
    return network


def _public_key(value: Any, label: str) -> str:
    text = str(value or "").strip()
    try:
        decoded = base64.b64decode(text, validate=True)
    except (binascii.Error, ValueError) as exc:
        raise RouterOSWireGuardRenderError(f"{label} must be base64") from exc
    if len(decoded) != 32:
        raise RouterOSWireGuardRenderError(f"{label} must decode to exactly 32 bytes")
    return text


def _endpoint(value: Any, label: str) -> str:
    text = str(value or "").strip()
    if not text:
        raise RouterOSWireGuardRenderError(f"{label} must not be empty")
    try:
        address = ipaddress.ip_address(text)
    except ValueError:
        if not _HOST.fullmatch(text) or ".." in text:
            raise RouterOSWireGuardRenderError(f"{label} must be an IP address or conservative DNS name")
    else:
        if address.is_unspecified or address.is_multicast:
            raise RouterOSWireGuardRenderError(f"{label} must be a usable endpoint")
    return text


@dataclass(frozen=True)
class RouterOSWireGuardTemplate:
    command_id: str
    section: str
    template: str
    secret_placeholders: tuple[str, ...] = ()
    risk: int = 30

    def as_dict(self) -> dict[str, Any]:
        return {
            "command_id": self.command_id,
            "section": self.section,
            "template": self.template,
            "secret_placeholders": list(self.secret_placeholders),
            "risk": self.risk,
        }


@dataclass(frozen=True)
class RouterOSWireGuardTemplatePlan:
    interface_name: str
    listen_port: int
    addresses: tuple[str, ...]
    peers: tuple[Mapping[str, Any], ...]
    templates: tuple[RouterOSWireGuardTemplate, ...]
    secret_ref: str

    def as_dict(self) -> dict[str, Any]:
        return {
            "schema_version": "routeros-wireguard-template-plan/1",
            "scope": "generation_only_deferred_secret_binding",
            "interface_name": self.interface_name,
            "listen_port": self.listen_port,
            "addresses": list(self.addresses),
            "peers": [dict(item) for item in self.peers],
            "command_templates": [item.as_dict() for item in self.templates],
            "template_count": len(self.templates),
            "secret_bindings": {
                PRIVATE_KEY_PLACEHOLDER: {
                    "reference": self.secret_ref,
                    "kind": "wireguard_private_key",
                    "resolved": False,
                }
            },
            "secrets_resolved": False,
            "transport_present": False,
            "apply_available": False,
            "write_authorized": False,
        }


def render_routeros_wireguard(*, ir: Mapping[str, Any]) -> RouterOSWireGuardTemplatePlan:
    """Render RouterOS WireGuard templates without resolving any private key.

    Templates are deliberately not executable product commands. The caller must
    keep the corresponding base-renderer blocker until a separately authorized
    secret-binding/transaction boundary exists. A disposable CHR lab may bind a
    synthetic ephemeral key solely for syntax/runtime validation.
    """

    _verify_ir(ir)
    operation = _operation(ir)
    attributes = operation.get("attributes", {})
    if not isinstance(attributes, Mapping):
        raise RouterOSWireGuardRenderError("vpn.wireguard attributes must be an object")
    if attributes.get("enabled") is not True:
        raise RouterOSWireGuardRenderError("WireGuard renderer requires enabled=true")

    refs = operation.get("secret_references", [])
    if not isinstance(refs, list) or len(refs) != 1:
        raise RouterOSWireGuardRenderError("WireGuard renderer requires exactly one unresolved private-key secret reference")
    secret_ref = str(refs[0] or "").strip()
    if not secret_ref.startswith(("env://", "vault://", "keyring://")):
        raise RouterOSWireGuardRenderError("WireGuard private-key reference uses an unsupported scheme")

    interface_name = _name(attributes.get("name"), "wireguard.name")
    listen_port = _port(attributes.get("listen_port"), "wireguard.listen_port")
    mtu = attributes.get("mtu")
    if isinstance(mtu, bool) or not isinstance(mtu, int) or not 1280 <= mtu <= 1500:
        raise RouterOSWireGuardRenderError("wireguard.mtu must be an integer from 1280 to 1500")

    raw_addresses = attributes.get("addresses")
    if not isinstance(raw_addresses, list) or not raw_addresses:
        raise RouterOSWireGuardRenderError("wireguard.addresses requires at least one explicit IPv4 interface CIDR")
    parsed_interfaces = tuple(
        sorted(
            {_ipv4_interface(value, "wireguard.addresses").with_prefixlen for value in raw_addresses}
        )
    )
    interface_networks = tuple(ipaddress.ip_interface(value).network for value in parsed_interfaces)
    local_ips = {ipaddress.ip_interface(value).ip for value in parsed_interfaces}

    raw_peers = attributes.get("peers")
    if not isinstance(raw_peers, list) or not raw_peers:
        raise RouterOSWireGuardRenderError("wireguard.peers requires at least one explicit peer")

    normalized_peers: list[dict[str, Any]] = []
    peer_names: set[str] = set()
    claimed_allowed: list[tuple[str, ipaddress.IPv4Network]] = []
    for index, item in enumerate(raw_peers):
        if not isinstance(item, Mapping):
            raise RouterOSWireGuardRenderError(f"wireguard.peers[{index}] must be an object")
        peer_name = _name(item.get("name"), f"wireguard.peers[{index}].name")
        if peer_name in peer_names:
            raise RouterOSWireGuardRenderError("wireguard peer names must be unique")
        peer_names.add(peer_name)
        public_key = _public_key(item.get("public_key"), f"wireguard.peers[{index}].public_key")
        tunnel = _ipv4_network(
            item.get("tunnel_address"),
            f"wireguard.peers[{index}].tunnel_address",
            require_host=True,
        )
        tunnel_ip = tunnel.network_address
        if tunnel_ip in local_ips or not any(tunnel_ip in network for network in interface_networks):
            raise RouterOSWireGuardRenderError(
                f"wireguard.peers[{index}].tunnel_address must be a remote /32 inside a configured WireGuard interface subnet"
            )

        raw_allowed = item.get("allowed_addresses")
        if not isinstance(raw_allowed, list) or not raw_allowed:
            raise RouterOSWireGuardRenderError(f"wireguard.peers[{index}].allowed_addresses must be a non-empty list")
        allowed = tuple(
            sorted(
                {
                    str(_ipv4_network(value, f"wireguard.peers[{index}].allowed_addresses"))
                    for value in raw_allowed
                }
            )
        )
        if str(tunnel) not in allowed:
            raise RouterOSWireGuardRenderError(
                f"wireguard.peers[{index}].allowed_addresses must include the explicit tunnel_address /32"
            )
        for cidr in allowed:
            network = ipaddress.ip_network(cidr)
            for previous_name, previous in claimed_allowed:
                if network.overlaps(previous):
                    raise RouterOSWireGuardRenderError(
                        f"WireGuard allowed-address ranges overlap between peers {previous_name!r} and {peer_name!r}"
                    )
            claimed_allowed.append((peer_name, network))

        raw_routes = item.get("routes", [])
        if not isinstance(raw_routes, list):
            raise RouterOSWireGuardRenderError(f"wireguard.peers[{index}].routes must be a list")
        routes = tuple(
            sorted(
                {
                    str(_ipv4_network(value, f"wireguard.peers[{index}].routes"))
                    for value in raw_routes
                }
            )
        )
        allowed_networks = [ipaddress.ip_network(value) for value in allowed]
        for route in routes:
            route_network = ipaddress.ip_network(route)
            if not any(route_network.subnet_of(candidate) for candidate in allowed_networks):
                raise RouterOSWireGuardRenderError(
                    f"wireguard.peers[{index}].routes must be contained by that peer's allowed_addresses"
                )

        endpoint_address = item.get("endpoint_address")
        endpoint_port = item.get("endpoint_port")
        endpoint: dict[str, Any] = {}
        if endpoint_address is not None or endpoint_port is not None:
            endpoint["endpoint_address"] = _endpoint(
                endpoint_address,
                f"wireguard.peers[{index}].endpoint_address",
            )
            endpoint["endpoint_port"] = _port(
                endpoint_port,
                f"wireguard.peers[{index}].endpoint_port",
            )
        keepalive = item.get("persistent_keepalive", 0)
        if isinstance(keepalive, bool) or not isinstance(keepalive, int) or not 0 <= keepalive <= 65535:
            raise RouterOSWireGuardRenderError(
                f"wireguard.peers[{index}].persistent_keepalive must be an integer from 0 to 65535"
            )
        responder = item.get("responder", False)
        if not isinstance(responder, bool):
            raise RouterOSWireGuardRenderError(f"wireguard.peers[{index}].responder must be boolean")

        normalized_peers.append(
            {
                "name": peer_name,
                "public_key": public_key,
                "tunnel_address": str(tunnel),
                "allowed_addresses": list(allowed),
                "routes": list(routes),
                **endpoint,
                "persistent_keepalive": keepalive,
                "responder": responder,
            }
        )

    normalized_peers.sort(key=lambda item: str(item["name"]))
    templates: list[RouterOSWireGuardTemplate] = []
    name_q = _quote(interface_name)
    placeholder_q = _quote(PRIVATE_KEY_PLACEHOLDER)
    templates.append(
        RouterOSWireGuardTemplate(
            command_id="wireguard.10.interface",
            section="wireguard_interface",
            template=(
                f':local rid [/interface/wireguard/find where name={name_q}]; '
                f':if ([:len $rid] = 0) do={{/interface/wireguard/add name={name_q} listen-port={listen_port} mtu={mtu} private-key={placeholder_q} comment="routercfg:managed:wg:interface"}} '
                f'else={{/interface/wireguard/set $rid listen-port={listen_port} mtu={mtu} private-key={placeholder_q} comment="routercfg:managed:wg:interface"}}'
            ),
            secret_placeholders=(PRIVATE_KEY_PLACEHOLDER,),
        )
    )

    for index, address in enumerate(parsed_interfaces, start=1):
        comment = f"routercfg:managed:wg:address:{index:03d}"
        comment_q = _quote(comment)
        address_q = _quote(address)
        templates.append(
            RouterOSWireGuardTemplate(
                command_id=f"wireguard.20.address.{index:03d}",
                section="wireguard_address",
                template=(
                    f':local rid [/ip/address/find where comment={comment_q}]; '
                    f':if ([:len $rid] = 0) do={{/ip/address/add address={address_q} interface={name_q} comment={comment_q}}} '
                    f'else={{/ip/address/set $rid address={address_q} interface={name_q}}}'
                ),
            )
        )

    for peer_index, peer in enumerate(normalized_peers, start=1):
        comment = f"routercfg:managed:wg:peer:{peer_index:03d}"
        comment_q = _quote(comment)
        fields = [
            f"interface={name_q}",
            f"name={_quote(str(peer['name']))}",
            f"public-key={_quote(str(peer['public_key']))}",
            f"allowed-address={_quote(','.join(peer['allowed_addresses']))}",
            f"persistent-keepalive={int(peer['persistent_keepalive'])}",
            f"responder={'yes' if peer['responder'] else 'no'}",
            f"comment={comment_q}",
        ]
        if "endpoint_address" in peer:
            fields.extend(
                (
                    f"endpoint-address={_quote(str(peer['endpoint_address']))}",
                    f"endpoint-port={int(peer['endpoint_port'])}",
                )
            )
        assignment = " ".join(fields)
        templates.append(
            RouterOSWireGuardTemplate(
                command_id=f"wireguard.30.peer.{peer_index:03d}",
                section="wireguard_peer",
                template=(
                    f':local rid [/interface/wireguard/peers/find where comment={comment_q}]; '
                    f':if ([:len $rid] = 0) do={{/interface/wireguard/peers/add {assignment}}} '
                    f'else={{/interface/wireguard/peers/set $rid {assignment}}}'
                ),
            )
        )
        for route_index, route in enumerate(peer["routes"], start=1):
            route_comment = f"routercfg:managed:wg:route:{peer_index:03d}:{route_index:03d}"
            route_comment_q = _quote(route_comment)
            templates.append(
                RouterOSWireGuardTemplate(
                    command_id=f"wireguard.40.route.{peer_index:03d}.{route_index:03d}",
                    section="wireguard_route",
                    template=(
                        f':local rid [/ip/route/find where comment={route_comment_q}]; '
                        f':if ([:len $rid] = 0) do={{/ip/route/add dst-address={_quote(str(route))} gateway={name_q} comment={route_comment_q}}} '
                        f'else={{/ip/route/set $rid dst-address={_quote(str(route))} gateway={name_q}}}'
                    ),
                )
            )

    templates.sort(key=lambda item: item.command_id)
    return RouterOSWireGuardTemplatePlan(
        interface_name=interface_name,
        listen_port=listen_port,
        addresses=parsed_interfaces,
        peers=tuple(normalized_peers),
        templates=tuple(templates),
        secret_ref=secret_ref,
    )
