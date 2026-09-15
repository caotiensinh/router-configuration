"""Deterministic Cisco IOS XE switch normalized-state contract.

The normalizer consumes already decoded, source-bound YANG observations. It
never performs device writes and cannot by itself satisfy the C06 live gate.
Trunk operational state remains deliberately unverified until a source-bound
IOS XE model/path is admitted.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass
import hashlib
from importlib import resources
import json
import re
from typing import Iterable, Mapping, Sequence

from .platforms import CiscoDeviceRole, assess_read_only_candidate, documentation_train

_REQUIRED_MODULES = frozenset({
    "Cisco-IOS-XE-interfaces-oper",
    "Cisco-IOS-XE-vlan-oper",
    "Cisco-IOS-XE-matm-oper",
    "Cisco-IOS-XE-spanning-tree-oper",
})
_SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
_MAC_RE = re.compile(r"^(?:[0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}$")
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
_VLAN_STATES = frozenset({"active", "suspend"})
_MATM_ADDR_TYPES = frozenset({"static", "dynamic", "any"})
_STP_ROLES = frozenset({"stp-master", "stp-alternate", "stp-root", "stp-designated", "stp-backup"})
_STP_STATES = frozenset({
    "stp-disabled", "stp-blocking", "stp-listening", "stp-learning",
    "stp-forwarding", "stp-broken", "stp-invalid",
})


class CiscoSwitchStateError(ValueError):
    """Raised when switch-state evidence violates the source-bound contract."""


@dataclass(frozen=True)
class NormalizedSwitchInterface:
    name: str
    admin_status: str
    oper_status: str


@dataclass(frozen=True)
class NormalizedVlanPort:
    interface: str
    subinterface: int | None


@dataclass(frozen=True)
class NormalizedSwitchVlan:
    vlan_id: int
    name: str | None
    status: str
    ports: tuple[NormalizedVlanPort, ...]
    vlan_interfaces: tuple[NormalizedVlanPort, ...]


@dataclass(frozen=True)
class NormalizedMacEntry:
    vlan_id: int
    mac: str
    address_type: str
    port: str | None
    vlan_all: bool


@dataclass(frozen=True)
class NormalizedStpInterface:
    name: str
    role: str
    state: str
    cost: int | None
    port_priority: int | None
    port_number: int | None


@dataclass(frozen=True)
class NormalizedStpInstance:
    instance: str
    bridge_priority: int | None
    bridge_address: str | None
    designated_root_priority: int | None
    designated_root_address: str | None
    root_port: int | None
    root_cost: int | None
    topology_changes: int | None
    interfaces: tuple[NormalizedStpInterface, ...]


@dataclass(frozen=True)
class SwitchNormalizedState:
    model: str
    iosxe_version: str
    documentation_train: str
    platform_family: str
    schema_inventory_digest_sha256: str
    observed_modules: tuple[str, ...]
    interfaces: tuple[NormalizedSwitchInterface, ...]
    vlans: tuple[NormalizedSwitchVlan, ...]
    mac_entries: tuple[NormalizedMacEntry, ...]
    stp_instances: tuple[NormalizedStpInstance, ...]
    catalog_digest_sha256: str
    state_digest_sha256: str
    trunk_state_verified: bool = False
    c06_complete: bool = False
    production_write_authorized: bool = False
    physical_device_verified: bool = False

    def to_dict(self) -> dict:
        return asdict(self)


def _canonical_sha256(value: object) -> str:
    canonical = json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True)
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def load_switch_state_catalog() -> dict:
    package = resources.files("router_configuration.vendors.cisco.data")
    catalog = json.loads(package.joinpath("switch_state_catalog.json").read_text(encoding="utf-8"))
    _validate_catalog(catalog)
    return catalog


def switch_state_catalog_digest() -> str:
    return _canonical_sha256(load_switch_state_catalog())


def _validate_catalog(catalog: Mapping[str, object]) -> None:
    if catalog.get("schema_version") != "cisco-iosxe-switch-state-catalog/1":
        raise CiscoSwitchStateError("unsupported switch-state catalog schema")
    if catalog.get("vendor") != "Cisco" or catalog.get("os_family") != "IOS XE":
        raise CiscoSwitchStateError("switch-state catalog vendor/OS mismatch")
    if catalog.get("role") != "switch":
        raise CiscoSwitchStateError("switch-state catalog role mismatch")
    for key in ("write_authorized", "physical_device_verified", "synthetic_fixture_can_complete_c06", "trunk_state_verified"):
        if catalog.get(key) is not False:
            raise CiscoSwitchStateError(f"switch-state safety boundary must remain false: {key}")
    if catalog.get("live_state_evidence_required_for_c06") is not True:
        raise CiscoSwitchStateError("C06 must retain a live-state evidence gate")
    provenance = catalog.get("schema_provenance")
    if not isinstance(provenance, Mapping):
        raise CiscoSwitchStateError("switch-state schema provenance missing")
    if not re.fullmatch(r"[0-9a-f]{40}", str(provenance.get("yangmodels_commit", "")).lower()):
        raise CiscoSwitchStateError("switch-state YANG schema commit must be pinned")
    trains = catalog.get("documentation_trains")
    if not isinstance(trains, Mapping) or set(trains) != {"17.18", "26"}:
        raise CiscoSwitchStateError("switch-state documentation trains must be 17.18 and 26")
    observations = catalog.get("observations")
    if not isinstance(observations, list) or len(observations) != 4:
        raise CiscoSwitchStateError("switch-state catalog must define four admitted observations")
    modules = {str(item.get("module")) for item in observations if isinstance(item, Mapping)}
    if modules != _REQUIRED_MODULES:
        raise CiscoSwitchStateError("switch-state module set mismatch")
    if any(item.get("required_module_advertisement") is not True for item in observations):
        raise CiscoSwitchStateError("all switch-state models require runtime advertisement")
    unverified = catalog.get("unverified_observations")
    if not isinstance(unverified, list) or not any(isinstance(item, Mapping) and item.get("id") == "switch-trunk-operational-state" for item in unverified):
        raise CiscoSwitchStateError("trunk state must remain explicitly unverified")


def _reject_sensitive(value: object, path: str = "$") -> None:
    if isinstance(value, Mapping):
        for key, child in value.items():
            normalized = str(key).lower().replace("_", "-")
            if any(part.replace("_", "-") in normalized for part in _SENSITIVE_PARTS):
                raise CiscoSwitchStateError(f"sensitive field rejected at {path}")
            _reject_sensitive(child, f"{path}.{key}")
    elif isinstance(value, (list, tuple)):
        for index, child in enumerate(value):
            _reject_sensitive(child, f"{path}[{index}]")


def _bounded_text(value: object, field: str, *, required: bool = False, max_len: int = 255) -> str | None:
    if value is None:
        if required:
            raise CiscoSwitchStateError(f"missing required field: {field}")
        return None
    if not isinstance(value, str):
        raise CiscoSwitchStateError(f"field must be text: {field}")
    result = value.strip()
    if required and not result:
        raise CiscoSwitchStateError(f"missing required field: {field}")
    if len(result) > max_len or any(ord(char) < 32 for char in result):
        raise CiscoSwitchStateError(f"invalid text field: {field}")
    return result or None


def _uint(value: object, field: str, maximum: int) -> int | None:
    if value is None:
        return None
    if isinstance(value, bool) or not isinstance(value, int) or not 0 <= value <= maximum:
        raise CiscoSwitchStateError(f"invalid unsigned integer field: {field}")
    return value


def _mac(value: object, field: str, *, required: bool = False) -> str | None:
    text = _bounded_text(value, field, required=required, max_len=17)
    if text is None:
        return None
    if not _MAC_RE.fullmatch(text):
        raise CiscoSwitchStateError(f"invalid MAC address: {field}")
    return text.lower()


def _normalize_interface(record: Mapping[str, object]) -> NormalizedSwitchInterface:
    name = _bounded_text(record.get("name"), "interface.name", required=True, max_len=128)
    admin = _bounded_text(record.get("admin-status"), "interface.admin-status", required=True, max_len=64)
    oper = _bounded_text(record.get("oper-status"), "interface.oper-status", required=True, max_len=64)
    assert name is not None and admin is not None and oper is not None
    if admin not in _ADMIN_STATES:
        raise CiscoSwitchStateError(f"unsupported interface admin-status: {admin}")
    if oper not in _OPER_STATES:
        raise CiscoSwitchStateError(f"unsupported interface oper-status: {oper}")
    return NormalizedSwitchInterface(name=name, admin_status=admin, oper_status=oper)


def _normalize_vlan_port(record: Mapping[str, object], field: str) -> NormalizedVlanPort:
    interface = _bounded_text(record.get("interface"), f"{field}.interface", required=True, max_len=128)
    assert interface is not None
    return NormalizedVlanPort(interface=interface, subinterface=_uint(record.get("subinterface"), f"{field}.subinterface", 0xFFFFFFFF))


def _normalize_vlan(record: Mapping[str, object]) -> NormalizedSwitchVlan:
    vlan_id = _uint(record.get("id"), "vlan.id", 0xFFFF)
    if vlan_id is None:
        raise CiscoSwitchStateError("missing required field: vlan.id")
    status = _bounded_text(record.get("status"), "vlan.status", required=True, max_len=16)
    assert status is not None
    if status not in _VLAN_STATES:
        raise CiscoSwitchStateError(f"unsupported VLAN status: {status}")
    name = _bounded_text(record.get("name"), "vlan.name", max_len=64)

    def parse_ports(raw: object, field: str) -> tuple[NormalizedVlanPort, ...]:
        if raw is None:
            raw = []
        if not isinstance(raw, Sequence) or isinstance(raw, (str, bytes)):
            raise CiscoSwitchStateError(f"{field} must be a sequence")
        if any(not isinstance(item, Mapping) for item in raw):
            raise CiscoSwitchStateError(f"{field} entries must be objects")
        parsed = [_normalize_vlan_port(item, field) for item in raw]
        keys = [(item.interface, item.subinterface) for item in parsed]
        if len(set(keys)) != len(keys):
            raise CiscoSwitchStateError(f"duplicate {field} entry")
        return tuple(sorted(parsed, key=lambda item: (item.interface, -1 if item.subinterface is None else item.subinterface)))

    return NormalizedSwitchVlan(vlan_id=vlan_id, name=name, status=status, ports=parse_ports(record.get("ports"), "vlan.ports"), vlan_interfaces=parse_ports(record.get("vlan-interfaces"), "vlan.vlan-interfaces"))


def _normalize_mac(record: Mapping[str, object]) -> NormalizedMacEntry:
    table_type = _bounded_text(record.get("table-type"), "mac.table-type", required=True, max_len=32)
    if table_type != "mat-vlan":
        raise CiscoSwitchStateError("bounded switch MAC observation admits mat-vlan entries only")
    vlan_id = _uint(record.get("vlan-id-number"), "mac.vlan-id-number", 0xFFFFFFFF)
    if vlan_id is None:
        raise CiscoSwitchStateError("missing required field: mac.vlan-id-number")
    mac = _mac(record.get("mac"), "mac.mac", required=True)
    address_type = _bounded_text(record.get("mat-addr-type"), "mac.mat-addr-type", required=True, max_len=16)
    assert mac is not None and address_type is not None
    if address_type not in _MATM_ADDR_TYPES:
        raise CiscoSwitchStateError(f"unsupported MATM address type: {address_type}")
    port = _bounded_text(record.get("port"), "mac.port", max_len=128)
    vlan_all_raw = record.get("vlan-all", False)
    if vlan_all_raw not in (False, True, None):
        raise CiscoSwitchStateError("mac.vlan-all must represent YANG empty-leaf presence")
    return NormalizedMacEntry(vlan_id=vlan_id, mac=mac, address_type=address_type, port=port, vlan_all=vlan_all_raw is not False)


def _normalize_stp_interface(record: Mapping[str, object]) -> NormalizedStpInterface:
    name = _bounded_text(record.get("name"), "stp.interface.name", required=True, max_len=128)
    role = _bounded_text(record.get("role"), "stp.interface.role", required=True, max_len=32)
    state = _bounded_text(record.get("state"), "stp.interface.state", required=True, max_len=32)
    assert name is not None and role is not None and state is not None
    if role not in _STP_ROLES:
        raise CiscoSwitchStateError(f"unsupported STP port role: {role}")
    if state not in _STP_STATES:
        raise CiscoSwitchStateError(f"unsupported STP port state: {state}")
    return NormalizedStpInterface(name=name, role=role, state=state, cost=_uint(record.get("cost"), "stp.interface.cost", 0xFFFFFFFFFFFFFFFF), port_priority=_uint(record.get("port-priority"), "stp.interface.port-priority", 0xFFFF), port_number=_uint(record.get("port-num"), "stp.interface.port-num", 0xFFFF))


def _normalize_stp(record: Mapping[str, object]) -> NormalizedStpInstance:
    instance = _bounded_text(record.get("instance"), "stp.instance", required=True, max_len=128)
    assert instance is not None
    raw_interfaces = record.get("interfaces", [])
    if not isinstance(raw_interfaces, Sequence) or isinstance(raw_interfaces, (str, bytes)):
        raise CiscoSwitchStateError("stp.interfaces must be a sequence")
    if any(not isinstance(item, Mapping) for item in raw_interfaces):
        raise CiscoSwitchStateError("stp.interfaces entries must be objects")
    interfaces = [_normalize_stp_interface(item) for item in raw_interfaces]
    if len({item.name for item in interfaces}) != len(interfaces):
        raise CiscoSwitchStateError("duplicate STP interface name within instance")
    return NormalizedStpInstance(instance=instance, bridge_priority=_uint(record.get("bridge-priority"), "stp.bridge-priority", 0xFFFF), bridge_address=_mac(record.get("bridge-address"), "stp.bridge-address"), designated_root_priority=_uint(record.get("designated-root-priority"), "stp.designated-root-priority", 0xFFFFFFFF), designated_root_address=_mac(record.get("designated-root-address"), "stp.designated-root-address"), root_port=_uint(record.get("root-port"), "stp.root-port", 0xFFFF), root_cost=_uint(record.get("root-cost"), "stp.root-cost", 0xFFFFFFFFFFFFFFFF), topology_changes=_uint(record.get("topology-changes"), "stp.topology-changes", 0xFFFFFFFFFFFFFFFF), interfaces=tuple(sorted(interfaces, key=lambda item: item.name)))


def normalize_switch_state(*, model: str, iosxe_version: str, schema_inventory_digest_sha256: str, observed_modules: Iterable[str], interface_records: Sequence[Mapping[str, object]], vlan_records: Sequence[Mapping[str, object]], mac_records: Sequence[Mapping[str, object]], stp_records: Sequence[Mapping[str, object]]) -> SwitchNormalizedState:
    catalog = load_switch_state_catalog()
    decision = assess_read_only_candidate(model, iosxe_version)
    if not decision.read_only_candidate or decision.role is not CiscoDeviceRole.SWITCH:
        raise CiscoSwitchStateError(f"switch platform/version not admitted: {decision.status}")
    train = documentation_train(iosxe_version)
    if train not in catalog["documentation_trains"]:
        raise CiscoSwitchStateError("switch-state schema train is not source-bound")
    schema_digest = schema_inventory_digest_sha256.strip().lower()
    if not _SHA256_RE.fullmatch(schema_digest):
        raise CiscoSwitchStateError("valid live YANG inventory digest is required")
    modules = tuple(sorted({str(module).strip() for module in observed_modules if str(module).strip()}))
    missing = _REQUIRED_MODULES.difference(modules)
    if missing:
        raise CiscoSwitchStateError("required YANG modules were not advertised: " + ",".join(sorted(missing)))
    groups = {"interfaces": interface_records, "vlans": vlan_records, "mac": mac_records, "stp": stp_records}
    for name, records in groups.items():
        if not isinstance(records, Sequence) or isinstance(records, (str, bytes)):
            raise CiscoSwitchStateError(f"{name} records must be a sequence")
        _reject_sensitive(records, f"$.{name}")
    interfaces = tuple(sorted((_normalize_interface(item) for item in interface_records), key=lambda item: item.name))
    if len({item.name for item in interfaces}) != len(interfaces):
        raise CiscoSwitchStateError("duplicate interface name in switch state")
    vlans = tuple(sorted((_normalize_vlan(item) for item in vlan_records), key=lambda item: item.vlan_id))
    if len({item.vlan_id for item in vlans}) != len(vlans):
        raise CiscoSwitchStateError("duplicate VLAN id in switch state")
    mac_entries = tuple(sorted((_normalize_mac(item) for item in mac_records), key=lambda item: (item.vlan_id, item.mac)))
    if len({(item.vlan_id, item.mac) for item in mac_entries}) != len(mac_entries):
        raise CiscoSwitchStateError("duplicate MATM MAC key in bounded VLAN table")
    stp_instances = tuple(sorted((_normalize_stp(item) for item in stp_records), key=lambda item: item.instance))
    if len({item.instance for item in stp_instances}) != len(stp_instances):
        raise CiscoSwitchStateError("duplicate STP instance in switch state")
    state_payload = {"model": model.strip(), "iosxe_version": iosxe_version.strip(), "documentation_train": train, "platform_family": decision.family, "schema_inventory_digest_sha256": schema_digest, "observed_modules": modules, "interfaces": [asdict(item) for item in interfaces], "vlans": [asdict(item) for item in vlans], "mac_entries": [asdict(item) for item in mac_entries], "stp_instances": [asdict(item) for item in stp_instances], "trunk_state_verified": False}
    return SwitchNormalizedState(model=model.strip(), iosxe_version=iosxe_version.strip(), documentation_train=train, platform_family=decision.family or "", schema_inventory_digest_sha256=schema_digest, observed_modules=modules, interfaces=interfaces, vlans=vlans, mac_entries=mac_entries, stp_instances=stp_instances, catalog_digest_sha256=_canonical_sha256(catalog), state_digest_sha256=_canonical_sha256(state_payload))
