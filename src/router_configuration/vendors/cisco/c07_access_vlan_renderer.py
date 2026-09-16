"""Source-bound Cisco Native C07 access-VLAN renderer slice.

The pinned IOS XE 17.18.1 and 26.1.1 interface schemas expose the active
`switchport-wrapper/switchport/access/vlan` leaf as uint16 range 1..4094.
This conservative slice requires the caller to have already established that
the target is a switching port; it never changes switchport mode by itself.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass
import hashlib
import re
import xml.etree.ElementTree as ET

_NATIVE_NS = "http://cisco.com/ns/yang/Cisco-IOS-XE-native"
_FEATURE_ID = "switch.vlan.set"
_YANG_PATH = "/native/interface/GigabitEthernet[name]/switchport-wrapper/switchport/access/vlan"
_YANGMODELS_COMMIT = "a4ea86b06aa63512e280f1665db6eaf8116bf059"
_TRAINS = ("17.18", "26")
_INTERFACE_NAME = re.compile(r"^[A-Za-z0-9./:_-]{1,64}$")


class CiscoC07AccessVlanRendererError(ValueError):
    pass


@dataclass(frozen=True)
class C07AccessVlanFragment:
    feature_id: str
    yang_path: str
    yangmodels_commit: str
    documentation_trains: tuple[str, ...]
    interface_name: str
    vlan_id: int
    requires_existing_switchport: bool
    payload_xml: str
    payload_digest_sha256: str
    apply_authorized: bool = False
    production_write_authorized: bool = False

    def to_dict(self) -> dict:
        return asdict(self)


def _clean_interface_name(value: object) -> str:
    if not isinstance(value, str):
        raise CiscoC07AccessVlanRendererError("interface_name must be text")
    result = value.strip()
    if not _INTERFACE_NAME.fullmatch(result):
        raise CiscoC07AccessVlanRendererError("interface_name is outside the conservative renderer subset")
    return result


def _clean_vlan_id(value: object) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or not 1 <= value <= 4094:
        raise CiscoC07AccessVlanRendererError("vlan_id must be an integer in source-bound range 1..4094")
    return value


def render_access_vlan_fragment(*, interface_name: str, vlan_id: int) -> C07AccessVlanFragment:
    name = _clean_interface_name(interface_name)
    vlan = _clean_vlan_id(vlan_id)

    ET.register_namespace("", _NATIVE_NS)
    native = ET.Element(f"{{{_NATIVE_NS}}}native")
    interfaces = ET.SubElement(native, f"{{{_NATIVE_NS}}}interface")
    gigabit = ET.SubElement(interfaces, f"{{{_NATIVE_NS}}}GigabitEthernet")
    ET.SubElement(gigabit, f"{{{_NATIVE_NS}}}name").text = name
    wrapper = ET.SubElement(gigabit, f"{{{_NATIVE_NS}}}switchport-wrapper")
    switchport = ET.SubElement(wrapper, f"{{{_NATIVE_NS}}}switchport")
    access = ET.SubElement(switchport, f"{{{_NATIVE_NS}}}access")
    ET.SubElement(access, f"{{{_NATIVE_NS}}}vlan").text = str(vlan)
    payload_xml = ET.tostring(native, encoding="unicode", short_empty_elements=True)

    return C07AccessVlanFragment(
        feature_id=_FEATURE_ID,
        yang_path=_YANG_PATH,
        yangmodels_commit=_YANGMODELS_COMMIT,
        documentation_trains=_TRAINS,
        interface_name=name,
        vlan_id=vlan,
        requires_existing_switchport=True,
        payload_xml=payload_xml,
        payload_digest_sha256=hashlib.sha256(payload_xml.encode("utf-8")).hexdigest(),
    )
