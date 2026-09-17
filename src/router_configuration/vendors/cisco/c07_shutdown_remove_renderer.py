"""Source-bound C07 renderer for removing the Cisco Native shutdown leaf.

Cisco IOS XE 17.18.1 and 26.1.1 model interface shutdown as an active YANG
`empty` leaf. RFC 6241 section 7.2 defines NETCONF `operation=remove` as an
idempotent deletion: existing data is removed and missing data is ignored.
This module renders that candidate fragment only; it never sends edit-config.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass
import hashlib
import re
import xml.etree.ElementTree as ET

_NATIVE_NS = "http://cisco.com/ns/yang/Cisco-IOS-XE-native"
_NETCONF_NS = "urn:ietf:params:xml:ns:netconf:base:1.0"
_FEATURE_ID = "interface.shutdown.remove"
_YANG_PATH = "/native/interface/GigabitEthernet[name]/shutdown"
_YANGMODELS_COMMIT = "a4ea86b06aa63512e280f1665db6eaf8116bf059"
_TRAINS = ("17.18", "26")
_INTERFACE_NAME = re.compile(r"^[A-Za-z0-9./:_-]{1,64}$")


class CiscoC07ShutdownRemoveRendererError(ValueError):
    pass


@dataclass(frozen=True)
class C07ShutdownRemoveFragment:
    feature_id: str
    yang_path: str
    yangmodels_commit: str
    documentation_trains: tuple[str, ...]
    netconf_operation: str
    interface_name: str
    payload_xml: str
    payload_digest_sha256: str
    apply_authorized: bool = False
    production_write_authorized: bool = False

    def to_dict(self) -> dict:
        return asdict(self)


def _clean_interface_name(value: object) -> str:
    if not isinstance(value, str):
        raise CiscoC07ShutdownRemoveRendererError("interface_name must be text")
    result = value.strip()
    if not _INTERFACE_NAME.fullmatch(result):
        raise CiscoC07ShutdownRemoveRendererError("interface_name is outside the conservative renderer subset")
    return result


def render_shutdown_remove_fragment(*, interface_name: str) -> C07ShutdownRemoveFragment:
    name = _clean_interface_name(interface_name)
    ET.register_namespace("", _NATIVE_NS)
    ET.register_namespace("nc", _NETCONF_NS)
    native = ET.Element(f"{{{_NATIVE_NS}}}native")
    interfaces = ET.SubElement(native, f"{{{_NATIVE_NS}}}interface")
    gigabit = ET.SubElement(interfaces, f"{{{_NATIVE_NS}}}GigabitEthernet")
    ET.SubElement(gigabit, f"{{{_NATIVE_NS}}}name").text = name
    shutdown = ET.SubElement(gigabit, f"{{{_NATIVE_NS}}}shutdown")
    shutdown.set(f"{{{_NETCONF_NS}}}operation", "remove")
    payload_xml = ET.tostring(native, encoding="unicode", short_empty_elements=True)

    return C07ShutdownRemoveFragment(
        feature_id=_FEATURE_ID,
        yang_path=_YANG_PATH,
        yangmodels_commit=_YANGMODELS_COMMIT,
        documentation_trains=_TRAINS,
        netconf_operation="remove",
        interface_name=name,
        payload_xml=payload_xml,
        payload_digest_sha256=hashlib.sha256(payload_xml.encode("utf-8")).hexdigest(),
    )
