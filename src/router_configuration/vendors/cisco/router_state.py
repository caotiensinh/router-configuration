"""Deterministic Cisco IOS XE router normalized-state contract.

The normalizer consumes already decoded, source-bound YANG observations. It
never performs device writes and cannot by itself satisfy the C05 live gate.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass
import hashlib
from importlib import resources
import ipaddress
import json
import re
from typing import Iterable, Mapping, Sequence

from .platforms import CiscoDeviceRole, assess_read_only_candidate, documentation_train

_REQUIRED_MODULES = frozenset({"Cisco-IOS-XE-interfaces-oper", "ietf-routing"})
_SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
_SENSITIVE_PARTS = (
    "password", "secret", "private-key", "private_key", "pre-shared-key",
    "preshared-key", "psk", "token", "community", "key-string", "key_string",
)
_ADMIN_STATES = frozenset({"if-state-unknown", "if-state-up", "if-state-down", "if-state-test"})
_OPER_STATES = frozenset({
    "if-oper-state-invalid", "if-oper-state-ready", "if-oper-state-no-pass",
    "if-oper-state-test", "if-oper-state-unknown", "if-oper-state-dormant",
    "if-oper-state-not-present", "if-oper-state-lower-layer-down",
})
_SPECIAL_NEXT_HOPS = frozenset({"blackhole", "unreachable", "prohibit", "receive"})


class CiscoRouterStateError(ValueError):
    """Raised when router-state evidence violates the source-bound contract."""


@dataclass(frozen=True)
class NormalizedRouterInterface:
    name: str
    vrf: str | None
    admin_status: str
    oper_status: str
    ipv4_cidr: str | None
    ipv6_addresses: tuple[str, ...]


@dataclass(frozen=True)
class NormalizedRouterRoute:
    destination_prefix: str
    source_protocol: str
    route_preference: int | None
    metric: int | None
    outgoing_interface: str | None
    next_hop_address: str | None
    special_next_hop: str | None
    active: bool
    last_updated: str | None
    update_source: str | None


@dataclass(frozen=True)
class RouterNormalizedState:
    model: str
    iosxe_version: str
    documentation_train: str
    platform_family: str
    schema_inventory_digest_sha256: str
    observed_modules: tuple[str, ...]
    interfaces: tuple[NormalizedRouterInterface, ...]
    routes: tuple[NormalizedRouterRoute, ...]
    catalog_digest_sha256: str
    state_digest_sha256: str
    c05_complete: bool = False
    production_write_authorized: bool = False
    physical_device_verified: bool = False

    def to_dict(self) -> dict:
        return asdict(self)


def _canonical_sha256(value: object) -> str:
    canonical = json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True)
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def load_router_state_catalog() -> dict:
    package = resources.files("router_configuration.vendors.cisco.data")
    catalog = json.loads(package.joinpath("router_state_catalog.json").read_text(encoding="utf-8"))
    _validate_catalog(catalog)
    return catalog


def router_state_catalog_digest() -> str:
    return _canonical_sha256(load_router_state_catalog())


def _validate_catalog(catalog: Mapping[str, object]) -> None:
    if catalog.get("schema_version") != "cisco-iosxe-router-state-catalog/1":
        raise CiscoRouterStateError("unsupported router-state catalog schema")
    if catalog.get("vendor") != "Cisco" or catalog.get("os_family") != "IOS XE":
        raise CiscoRouterStateError("router-state catalog vendor/OS mismatch")
    if catalog.get("role") != "router":
        raise CiscoRouterStateError("router-state catalog role mismatch")
    for key in ("write_authorized", "physical_device_verified", "synthetic_fixture_can_complete_c05"):
        if catalog.get(key) is not False:
            raise CiscoRouterStateError(f"router-state safety boundary must remain false: {key}")
    if catalog.get("live_state_evidence_required_for_c05") is not True:
        raise CiscoRouterStateError("C05 must retain a live-state evidence gate")
    provenance = catalog.get("schema_provenance")
    if not isinstance(provenance, Mapping):
        raise CiscoRouterStateError("router-state schema provenance missing")
    if not re.fullmatch(r"[0-9a-f]{40}", str(provenance.get("yangmodels_commit", "")).lower()):
        raise CiscoRouterStateError("router-state YANG schema commit must be pinned")
    trains = catalog.get("documentation_trains")
    if not isinstance(trains, Mapping) or set(trains) != {"17.18", "26"}:
        raise CiscoRouterStateError("router-state documentation trains must be 17.18 and 26")
    observations = catalog.get("observations")
    if not isinstance(observations, list) or len(observations) != 2:
        raise CiscoRouterStateError("router-state catalog must define two bounded observations")
    modules = {str(item.get("module")) for item in observations if isinstance(item, Mapping)}
    if modules != _REQUIRED_MODULES:
        raise CiscoRouterStateError("router-state module set mismatch")
    if any(item.get("required_module_advertisement") is not True for item in observations):
        raise CiscoRouterStateError("all router-state models require runtime advertisement")


def _reject_sensitive(value: object, path: str = "$") -> None:
    if isinstance(value, Mapping):
        for key, child in value.items():
            normalized = str(key).lower().replace("_", "-")
            if any(part.replace("_", "-") in normalized for part in _SENSITIVE_PARTS):
                raise CiscoRouterStateError(f"sensitive field rejected at {path}")
            _reject_sensitive(child, f"{path}.{key}")
    elif isinstance(value, (list, tuple)):
        for index, child in enumerate(value):
            _reject_sensitive(child, f"{path}[{index}]")


def _bounded_text(value: object, field: str, *, required: bool = False, max_len: int = 255) -> str | None:
    if value is None:
        if required:
            raise CiscoRouterStateError(f"missing required field: {field}")
        return None
    if not isinstance(value, str):
        raise CiscoRouterStateError(f"field must be text: {field}")
    result = value.strip()
    if required and not result:
        raise CiscoRouterStateError(f"missing required field: {field}")
    if len(result) > max_len or any(ord(char) < 32 for char in result):
        raise CiscoRouterStateError(f"invalid text field: {field}")
    return result or None


def _uint32(value: object, field: str) -> int | None:
    if value is None:
        return None
    if isinstance(value, bool) or not isinstance(value, int) or not 0 <= value <= 0xFFFFFFFF:
        raise CiscoRouterStateError(f"invalid uint32 field: {field}")
    return value


def _normalize_interface(record: Mapping[str, object]) -> NormalizedRouterInterface:
    name = _bounded_text(record.get("name"), "interface.name", required=True, max_len=128)
    admin = _bounded_text(record.get("admin-status"), "interface.admin-status", required=True, max_len=64)
    oper = _bounded_text(record.get("oper-status"), "interface.oper-status", required=True, max_len=64)
    assert name is not None and admin is not None and oper is not None
    if admin not in _ADMIN_STATES:
        raise CiscoRouterStateError(f"unsupported interface admin-status: {admin}")
    if oper not in _OPER_STATES:
        raise CiscoRouterStateError(f"unsupported interface oper-status: {oper}")
    vrf = _bounded_text(record.get("vrf"), "interface.vrf", max_len=128)
    ipv4 = _bounded_text(record.get("ipv4"), "interface.ipv4", max_len=64)
    mask = _bounded_text(record.get("ipv4-subnet-mask"), "interface.ipv4-subnet-mask", max_len=64)
    if bool(ipv4) != bool(mask):
        raise CiscoRouterStateError("IPv4 address and subnet mask must be observed together")
    ipv4_cidr = None
    if ipv4 and mask:
        try:
            address = ipaddress.IPv4Address(ipv4)
            prefix = ipaddress.IPv4Network(f"0.0.0.0/{mask}").prefixlen
        except (ipaddress.AddressValueError, ipaddress.NetmaskValueError) as exc:
            raise CiscoRouterStateError("invalid interface IPv4 address or subnet mask") from exc
        ipv4_cidr = f"{address}/{prefix}"
    raw_ipv6 = record.get("ipv6-addrs", [])
    if raw_ipv6 is None:
        raw_ipv6 = []
    if not isinstance(raw_ipv6, (list, tuple)):
        raise CiscoRouterStateError("interface.ipv6-addrs must be a list")
    ipv6_values: set[str] = set()
    for value in raw_ipv6:
        if not isinstance(value, str):
            raise CiscoRouterStateError("IPv6 address must be text")
        try:
            parsed = ipaddress.IPv6Address(value.strip())
        except ipaddress.AddressValueError as exc:
            raise CiscoRouterStateError("invalid interface IPv6 address") from exc
        ipv6_values.add(str(parsed))
    return NormalizedRouterInterface(
        name=name, vrf=vrf, admin_status=admin, oper_status=oper,
        ipv4_cidr=ipv4_cidr, ipv6_addresses=tuple(sorted(ipv6_values)),
    )


def _normalize_route(record: Mapping[str, object]) -> NormalizedRouterRoute:
    prefix = _bounded_text(record.get("destination-prefix"), "route.destination-prefix", required=True, max_len=64)
    source = _bounded_text(record.get("source-protocol"), "route.source-protocol", required=True, max_len=128)
    assert prefix is not None and source is not None
    try:
        network = ipaddress.ip_network(prefix, strict=True)
    except ValueError as exc:
        raise CiscoRouterStateError("invalid route destination-prefix") from exc
    if not isinstance(network, ipaddress.IPv4Network):
        raise CiscoRouterStateError("bounded ipv4-default RIB observation must contain IPv4 prefixes only")
    next_hop = record.get("next-hop")
    if not isinstance(next_hop, Mapping):
        raise CiscoRouterStateError("route.next-hop must be an object")
    outgoing = _bounded_text(next_hop.get("outgoing-interface"), "route.next-hop.outgoing-interface", max_len=128)
    address = _bounded_text(next_hop.get("next-hop-address"), "route.next-hop.next-hop-address", max_len=64)
    special = _bounded_text(next_hop.get("special-next-hop"), "route.next-hop.special-next-hop", max_len=32)
    if special:
        if special not in _SPECIAL_NEXT_HOPS or outgoing or address:
            raise CiscoRouterStateError("invalid special next-hop choice")
    else:
        if not outgoing and not address:
            raise CiscoRouterStateError("simple next-hop requires interface or address")
        if address:
            try:
                address = str(ipaddress.ip_address(address))
            except ValueError as exc:
                raise CiscoRouterStateError("invalid route next-hop address") from exc
    return NormalizedRouterRoute(
        destination_prefix=str(network), source_protocol=source,
        route_preference=_uint32(record.get("route-preference"), "route.route-preference"),
        metric=_uint32(record.get("metric"), "route.metric"),
        outgoing_interface=outgoing, next_hop_address=address, special_next_hop=special,
        active="active" in record and record.get("active") is not False,
        last_updated=_bounded_text(record.get("last-updated"), "route.last-updated", max_len=128),
        update_source=_bounded_text(record.get("update-source"), "route.update-source", max_len=128),
    )


def normalize_router_state(
    *,
    model: str,
    iosxe_version: str,
    schema_inventory_digest_sha256: str,
    observed_modules: Iterable[str],
    interface_records: Sequence[Mapping[str, object]],
    route_records: Sequence[Mapping[str, object]],
) -> RouterNormalizedState:
    catalog = load_router_state_catalog()
    decision = assess_read_only_candidate(model, iosxe_version)
    if not decision.read_only_candidate or decision.role is not CiscoDeviceRole.ROUTER:
        raise CiscoRouterStateError(f"router platform/version not admitted: {decision.status}")
    train = documentation_train(iosxe_version)
    if train not in catalog["documentation_trains"]:
        raise CiscoRouterStateError("router-state schema train is not source-bound")
    schema_digest = schema_inventory_digest_sha256.strip().lower()
    if not _SHA256_RE.fullmatch(schema_digest):
        raise CiscoRouterStateError("valid live YANG inventory digest is required")
    modules = tuple(sorted({str(module).strip() for module in observed_modules if str(module).strip()}))
    missing = _REQUIRED_MODULES.difference(modules)
    if missing:
        raise CiscoRouterStateError("required YANG modules were not advertised: " + ",".join(sorted(missing)))
    if not isinstance(interface_records, Sequence) or isinstance(interface_records, (str, bytes)):
        raise CiscoRouterStateError("interface records must be a sequence")
    if not isinstance(route_records, Sequence) or isinstance(route_records, (str, bytes)):
        raise CiscoRouterStateError("route records must be a sequence")
    _reject_sensitive(interface_records, "$.interfaces")
    _reject_sensitive(route_records, "$.routes")
    interfaces = tuple(sorted((_normalize_interface(item) for item in interface_records), key=lambda item: item.name))
    if len({item.name for item in interfaces}) != len(interfaces):
        raise CiscoRouterStateError("duplicate interface name in router state")
    routes = tuple(sorted(
        (_normalize_route(item) for item in route_records),
        key=lambda item: item.destination_prefix,
    ))
    if len({item.destination_prefix for item in routes}) != len(routes):
        raise CiscoRouterStateError("duplicate destination-prefix in bounded default IPv4 RIB observation")
    state_payload = {
        "model": model.strip(), "iosxe_version": iosxe_version.strip(),
        "documentation_train": train, "platform_family": decision.family,
        "schema_inventory_digest_sha256": schema_digest, "observed_modules": modules,
        "interfaces": [asdict(item) for item in interfaces],
        "routes": [asdict(item) for item in routes],
    }
    return RouterNormalizedState(
        model=model.strip(), iosxe_version=iosxe_version.strip(), documentation_train=train,
        platform_family=decision.family or "", schema_inventory_digest_sha256=schema_digest,
        observed_modules=modules, interfaces=interfaces, routes=routes,
        catalog_digest_sha256=_canonical_sha256(catalog),
        state_digest_sha256=_canonical_sha256(state_payload),
    )
