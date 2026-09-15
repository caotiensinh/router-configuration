"""Deterministic, source-bound Cisco IOS XE desired-state rendering.

This module renders candidate configuration fragments only. It never opens a
network connection, invokes NETCONF, applies configuration, or grants approval.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass
import hashlib
from importlib import resources
import json
import re
from typing import Iterable, Mapping
import xml.etree.ElementTree as ET

from .platforms import assess_read_only_candidate, documentation_train

_IOSXE_NATIVE_NS = "http://cisco.com/ns/yang/Cisco-IOS-XE-native"
_FEATURE_ID = "interface.description.set"
_REQUIRED_MODULE = "Cisco-IOS-XE-native"
_CANDIDATE_CAPABILITY = "urn:ietf:params:netconf:capability:candidate:1.0"
_SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
_INTERFACE_NAME_RE = re.compile(r"^[A-Za-z0-9./:_-]{1,64}$")


class CiscoDesiredStateError(ValueError):
    """Raised when desired-state input violates the source-bound contract."""


@dataclass(frozen=True)
class DesiredStateRender:
    model: str
    iosxe_version: str
    documentation_train: str
    platform_family: str
    role: str
    feature_id: str
    target_datastore: str
    required_module: str
    schema_inventory_digest_sha256: str
    catalog_digest_sha256: str
    payload_digest_sha256: str
    payload_xml: str
    c07_complete: bool = False
    approval_bound: bool = False
    apply_authorized: bool = False
    production_write_authorized: bool = False

    def to_dict(self) -> dict:
        return asdict(self)


def _canonical_sha256(value: object) -> str:
    canonical = json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True)
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def load_desired_state_catalog() -> dict:
    package = resources.files("router_configuration.vendors.cisco.data")
    catalog = json.loads(package.joinpath("desired_state_catalog.json").read_text(encoding="utf-8"))
    _validate_catalog(catalog)
    return catalog


def desired_state_catalog_digest() -> str:
    return _canonical_sha256(load_desired_state_catalog())


def _validate_catalog(catalog: Mapping[str, object]) -> None:
    if catalog.get("schema_version") != "cisco-iosxe-desired-state-catalog/1":
        raise CiscoDesiredStateError("unsupported desired-state catalog schema")
    if catalog.get("vendor") != "Cisco" or catalog.get("os_family") != "IOS XE":
        raise CiscoDesiredStateError("desired-state catalog vendor/OS mismatch")
    for key in (
        "runtime_ai_rendering",
        "write_authorized",
        "production_write_authorized",
        "c07_complete",
    ):
        if catalog.get(key) is not False:
            raise CiscoDesiredStateError(f"desired-state safety boundary must remain false: {key}")

    provenance = catalog.get("schema_provenance")
    if not isinstance(provenance, Mapping):
        raise CiscoDesiredStateError("desired-state schema provenance missing")
    if not re.fullmatch(r"[0-9a-f]{40}", str(provenance.get("yangmodels_commit", "")).lower()):
        raise CiscoDesiredStateError("desired-state YANG schema commit must be pinned")

    trains = catalog.get("documentation_trains")
    if not isinstance(trains, Mapping) or set(trains) != {"17.18", "26"}:
        raise CiscoDesiredStateError("desired-state documentation trains must be 17.18 and 26")

    features = catalog.get("features")
    if not isinstance(features, list) or len(features) != 1 or not isinstance(features[0], Mapping):
        raise CiscoDesiredStateError("desired-state catalog must define exactly one bounded slice")
    feature = features[0]
    if feature.get("id") != _FEATURE_ID:
        raise CiscoDesiredStateError("unexpected desired-state feature id")
    if feature.get("transport") != "netconf" or feature.get("target_datastore") != "candidate":
        raise CiscoDesiredStateError("desired-state slice must target NETCONF candidate")
    if feature.get("module") != _REQUIRED_MODULE or feature.get("required_module_advertisement") is not True:
        raise CiscoDesiredStateError("desired-state native module binding mismatch")
    capabilities = feature.get("required_capabilities")
    if capabilities != [_CANDIDATE_CAPABILITY]:
        raise CiscoDesiredStateError("desired-state candidate capability binding mismatch")
    constraints = feature.get("yang_constraints")
    if not isinstance(constraints, Mapping) or constraints.get("description_length") != [0, 200]:
        raise CiscoDesiredStateError("desired-state YANG description constraint mismatch")
    renderer = feature.get("renderer_constraints")
    if not isinstance(renderer, Mapping) or renderer.get("nonempty_description") is not True:
        raise CiscoDesiredStateError("desired-state renderer must retain its conservative subset")


def _clean_text(value: object, field: str, *, max_len: int, nonempty: bool = True) -> str:
    if not isinstance(value, str):
        raise CiscoDesiredStateError(f"field must be text: {field}")
    result = value.strip()
    if nonempty and not result:
        raise CiscoDesiredStateError(f"missing required field: {field}")
    if len(result) > max_len:
        raise CiscoDesiredStateError(f"field exceeds source-bound length: {field}")
    if any(ord(char) < 32 or ord(char) == 127 for char in result):
        raise CiscoDesiredStateError(f"control character rejected: {field}")
    return result


def render_interface_description(
    *,
    model: str,
    iosxe_version: str,
    schema_inventory_digest_sha256: str,
    observed_modules: Iterable[str],
    netconf_capabilities: Iterable[str],
    interface_name: str,
    description: str,
) -> DesiredStateRender:
    """Render a deterministic Cisco Native candidate fragment for one description."""

    catalog = load_desired_state_catalog()
    decision = assess_read_only_candidate(model, iosxe_version)
    if not decision.read_only_candidate or decision.role is None:
        raise CiscoDesiredStateError(f"platform/version not admitted: {decision.status}")

    train = documentation_train(iosxe_version)
    if train not in catalog["documentation_trains"]:
        raise CiscoDesiredStateError("desired-state schema train is not source-bound")

    schema_digest = schema_inventory_digest_sha256.strip().lower()
    if not _SHA256_RE.fullmatch(schema_digest):
        raise CiscoDesiredStateError("valid YANG inventory digest is required")

    modules = {str(item).strip() for item in observed_modules if str(item).strip()}
    if _REQUIRED_MODULE not in modules:
        raise CiscoDesiredStateError("required Cisco-IOS-XE-native module was not advertised")

    capabilities = {str(item).strip() for item in netconf_capabilities if str(item).strip()}
    if _CANDIDATE_CAPABILITY not in capabilities:
        raise CiscoDesiredStateError("NETCONF candidate capability was not advertised")

    name = _clean_text(interface_name, "interface_name", max_len=64)
    if not _INTERFACE_NAME_RE.fullmatch(name):
        raise CiscoDesiredStateError("interface_name is outside the conservative renderer subset")
    value = _clean_text(description, "description", max_len=200)

    ET.register_namespace("", _IOSXE_NATIVE_NS)
    native = ET.Element(f"{{{_IOSXE_NATIVE_NS}}}native")
    interfaces = ET.SubElement(native, f"{{{_IOSXE_NATIVE_NS}}}interface")
    gigabit = ET.SubElement(interfaces, f"{{{_IOSXE_NATIVE_NS}}}GigabitEthernet")
    ET.SubElement(gigabit, f"{{{_IOSXE_NATIVE_NS}}}name").text = name
    ET.SubElement(gigabit, f"{{{_IOSXE_NATIVE_NS}}}description").text = value
    payload_xml = ET.tostring(native, encoding="unicode", short_empty_elements=True)

    payload_digest = hashlib.sha256(payload_xml.encode("utf-8")).hexdigest()
    return DesiredStateRender(
        model=model.strip(),
        iosxe_version=iosxe_version.strip(),
        documentation_train=train,
        platform_family=decision.family or "",
        role=decision.role.value,
        feature_id=_FEATURE_ID,
        target_datastore="candidate",
        required_module=_REQUIRED_MODULE,
        schema_inventory_digest_sha256=schema_digest,
        catalog_digest_sha256=_canonical_sha256(catalog),
        payload_digest_sha256=payload_digest,
        payload_xml=payload_xml,
    )
