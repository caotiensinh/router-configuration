"""Source-bound Cisco Native C07 IPv4 primary renderer slice.

Pinned YangModels commit a4ea86b06aa63512e280f1665db6eaf8116bf059
shows the same active `ip/address/primary/address` and `mask` structure for the
IOS XE 17.18.1 and 26.1.1 interface schemas. This module only renders a
candidate fragment; it never opens a network connection or authorizes apply.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass
import hashlib
import ipaddress
import re
import xml.etree.ElementTree as ET

_NATIVE_NS = "http://cisco.com/ns/yang/Cisco-IOS-XE-native"
_FEATURE_ID = "interface.ipv4.set"
_YANG_PATH = "/native/interface/GigabitEthernet[name]/ip/address/primary"
_YANGMODELS_COMMIT = "a4ea86b06aa63512e280f1665db6eaf8116bf059"
_TRAINS = ("17.18", "26")
_INTERFACE_NAME = re.compile(r"^[A-Za-z0-9./:_-]{1,64}$")


class CiscoC07Ipv4RendererError(ValueError):
    pass


@dataclass(frozen=True)
class C07Ipv4Fragment:
    feature_id: str
    yang_path: str
    yangmodels_commit: str
    documentation_trains: tuple[str, ...]
    interface_name: str
    address: str
    mask: str
    payload_xml: str
    payload_digest_sha256: str
    apply_authorized: bool = False
    production_write_authorized: bool = False

    def to_dict(self) -> dict:
        return asdict(self)


def _clean_interface_name(value: object) -> str:
    if not isinstance(value, str):
        raise CiscoC07Ipv4RendererError("interface_name must be text")
    result = value.strip()
    if not _INTERFACE_NAME.fullmatch(result):
        raise CiscoC07Ipv4RendererError("interface_name is outside the conservative renderer subset")
    return result


def _clean_ipv4(value: object, field: str) -> str:
    if not isinstance(value, str):
        raise CiscoC07Ipv4RendererError(f"{field} must be text")
    try:
        return str(ipaddress.IPv4Address(value.strip()))
    except ipaddress.AddressValueError as exc:
        raise CiscoC07Ipv4RendererError(f"invalid {field}") from exc


def _clean_mask(value: object) -> str:
    mask = _clean_ipv4(value, "mask")
    try:
        ipaddress.IPv4Network(f"0.0.0.0/{mask}")
    except ipaddress.NetmaskValueError as exc:
        raise CiscoC07Ipv4RendererError("mask must be a contiguous IPv4 netmask") from exc
    return mask


def render_ipv4_primary_fragment(*, interface_name: str, address: str, mask: str) -> C07Ipv4Fragment:
    name = _clean_interface_name(interface_name)
    clean_address = _clean_ipv4(address, "address")
    clean_mask = _clean_mask(mask)

    ET.register_namespace("", _NATIVE_NS)
    native = ET.Element(f"{{{_NATIVE_NS}}}native")
    interfaces = ET.SubElement(native, f"{{{_NATIVE_NS}}}interface")
    gigabit = ET.SubElement(interfaces, f"{{{_NATIVE_NS}}}GigabitEthernet")
    ET.SubElement(gigabit, f"{{{_NATIVE_NS}}}name").text = name
    ip = ET.SubElement(gigabit, f"{{{_NATIVE_NS}}}ip")
    address_node = ET.SubElement(ip, f"{{{_NATIVE_NS}}}address")
    primary = ET.SubElement(address_node, f"{{{_NATIVE_NS}}}primary")
    ET.SubElement(primary, f"{{{_NATIVE_NS}}}address").text = clean_address
    ET.SubElement(primary, f"{{{_NATIVE_NS}}}mask").text = clean_mask
    payload_xml = ET.tostring(native, encoding="unicode", short_empty_elements=True)

    return C07Ipv4Fragment(
        feature_id=_FEATURE_ID,
        yang_path=_YANG_PATH,
        yangmodels_commit=_YANGMODELS_COMMIT,
        documentation_trains=_TRAINS,
        interface_name=name,
        address=clean_address,
        mask=clean_mask,
        payload_xml=payload_xml,
        payload_digest_sha256=hashlib.sha256(payload_xml.encode("utf-8")).hexdigest(),
    )
