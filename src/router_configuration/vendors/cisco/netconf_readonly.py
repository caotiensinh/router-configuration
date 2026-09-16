"""Fail-closed Cisco IOS XE NETCONF read-only evidence primitives."""

from __future__ import annotations

from dataclasses import dataclass
import hashlib
import json
from typing import Iterable
from urllib.parse import parse_qs
from xml.etree import ElementTree as ET

NETCONF_BASE_NS = "urn:ietf:params:xml:ns:netconf:base:1.0"
NETCONF_MONITORING_NS = "urn:ietf:params:xml:ns:yang:ietf-netconf-monitoring"
CISCO_NATIVE_NS = "http://cisco.com/ns/yang/Cisco-IOS-XE-native"

MAX_NETCONF_XML_BYTES = 512 * 1024

_ALLOWED_RPC_TAGS = {
    (NETCONF_BASE_NS, "get"),
    (NETCONF_BASE_NS, "get-config"),
    (NETCONF_MONITORING_NS, "get-schema"),
}
_BLOCKED_OPERATION_NAMES = {
    "edit-config",
    "copy-config",
    "delete-config",
    "commit",
    "discard-changes",
    "lock",
    "unlock",
    "kill-session",
    "action",
}
_SENSITIVE_LOCAL_NAMES = {
    "password",
    "secret",
    "private-key",
    "private_key",
    "preshared-key",
    "pre-shared-key",
    "psk",
    "community",
    "token",
    "key-string",
}


class CiscoNetconfEvidenceError(ValueError):
    """Raised when NETCONF evidence or an RPC violates the read-only contract."""


@dataclass(frozen=True)
class NetconfCapability:
    raw_uri: str
    module: str | None
    revision: str | None
    features: tuple[str, ...]
    deviations: tuple[str, ...]


@dataclass(frozen=True)
class NetconfHelloEvidence:
    session_id: int
    base_capabilities: tuple[str, ...]
    capabilities: tuple[NetconfCapability, ...]
    model_modules: tuple[str, ...]
    digest_sha256: str
    write_authorized: bool = False
    physical_device_verified: bool = False


@dataclass(frozen=True)
class NetconfSchemaRecord:
    identifier: str
    version: str | None
    format: str | None
    namespace: str | None
    locations: tuple[str, ...]


@dataclass(frozen=True)
class NetconfSchemaInventory:
    schemas: tuple[NetconfSchemaRecord, ...]
    digest_sha256: str
    write_authorized: bool = False


@dataclass(frozen=True)
class NetconfReadOnlyRpcDecision:
    operation: str
    namespace: str
    allowed: bool
    reason: str


def _split_tag(tag: str) -> tuple[str, str]:
    if tag.startswith("{") and "}" in tag:
        namespace, local_name = tag[1:].split("}", 1)
        return namespace, local_name
    return "", tag


def _parse_xml(xml_text: str) -> ET.Element:
    if not isinstance(xml_text, str) or not xml_text.strip():
        raise CiscoNetconfEvidenceError("NETCONF XML must be a non-empty string")
    encoded = xml_text.encode("utf-8")
    if len(encoded) > MAX_NETCONF_XML_BYTES:
        raise CiscoNetconfEvidenceError("NETCONF XML exceeds the bounded evidence size")
    upper = xml_text.upper()
    if "<!DOCTYPE" in upper or "<!ENTITY" in upper:
        raise CiscoNetconfEvidenceError("DTD/entity declarations are not accepted")
    try:
        return ET.fromstring(xml_text)
    except ET.ParseError as exc:
        raise CiscoNetconfEvidenceError(f"invalid NETCONF XML: {exc}") from exc


def _canonical_sha256(value: object) -> str:
    canonical = json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True)
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def _capability_fields(uri: str) -> NetconfCapability:
    _, separator, query = uri.partition("?")
    params = parse_qs(query, keep_blank_values=True) if separator else {}

    def first(name: str) -> str | None:
        values = params.get(name, [])
        if not values:
            return None
        value = values[0].strip()
        return value or None

    def csv(name: str) -> tuple[str, ...]:
        value = first(name)
        if value is None:
            return ()
        return tuple(sorted(part.strip() for part in value.split(",") if part.strip()))

    return NetconfCapability(
        raw_uri=uri,
        module=first("module"),
        revision=first("revision"),
        features=csv("features"),
        deviations=csv("deviations"),
    )


def parse_server_hello(xml_text: str) -> NetconfHelloEvidence:
    root = _parse_xml(xml_text)
    namespace, local_name = _split_tag(root.tag)
    if (namespace, local_name) != (NETCONF_BASE_NS, "hello"):
        raise CiscoNetconfEvidenceError("expected NETCONF <hello> in the base namespace")

    capabilities_parent = root.find(f"{{{NETCONF_BASE_NS}}}capabilities")
    session_element = root.find(f"{{{NETCONF_BASE_NS}}}session-id")
    if capabilities_parent is None or session_element is None:
        raise CiscoNetconfEvidenceError("NETCONF hello must contain capabilities and session-id")

    session_text = (session_element.text or "").strip()
    if not session_text.isdigit() or int(session_text) <= 0:
        raise CiscoNetconfEvidenceError("NETCONF session-id must be a positive integer")
    session_id = int(session_text)

    raw_capabilities: list[str] = []
    for element in capabilities_parent.findall(f"{{{NETCONF_BASE_NS}}}capability"):
        value = (element.text or "").strip()
        if value:
            raw_capabilities.append(value)
    if not raw_capabilities:
        raise CiscoNetconfEvidenceError("NETCONF hello advertised no capabilities")
    if len(raw_capabilities) != len(set(raw_capabilities)):
        raise CiscoNetconfEvidenceError("NETCONF hello contains duplicate capability URIs")

    base_capabilities = tuple(
        sorted(
            value
            for value in raw_capabilities
            if value in {
                "urn:ietf:params:netconf:base:1.0",
                "urn:ietf:params:netconf:base:1.1",
            }
        )
    )
    if not base_capabilities:
        raise CiscoNetconfEvidenceError("NETCONF hello lacks base:1.0/base:1.1 capability")

    capabilities = tuple(
        sorted((_capability_fields(value) for value in raw_capabilities), key=lambda item: item.raw_uri)
    )
    model_modules = tuple(sorted({item.module for item in capabilities if item.module}))
    digest_payload = {
        "session_id": session_id,
        "base_capabilities": base_capabilities,
        "capabilities": [
            {
                "raw_uri": item.raw_uri,
                "module": item.module,
                "revision": item.revision,
                "features": item.features,
                "deviations": item.deviations,
            }
            for item in capabilities
        ],
        "model_modules": model_modules,
        "write_authorized": False,
        "physical_device_verified": False,
    }
    return NetconfHelloEvidence(
        session_id=session_id,
        base_capabilities=base_capabilities,
        capabilities=capabilities,
        model_modules=model_modules,
        digest_sha256=_canonical_sha256(digest_payload),
    )


def _iter_local_names(root: ET.Element) -> Iterable[str]:
    for element in root.iter():
        yield _split_tag(element.tag)[1].lower()


def _reject_sensitive_response(root: ET.Element) -> None:
    found = sorted(set(_iter_local_names(root)).intersection(_SENSITIVE_LOCAL_NAMES))
    if found:
        raise CiscoNetconfEvidenceError(
            "read-only evidence response contains sensitive fields: " + ", ".join(found)
        )


def validate_read_only_rpc(xml_text: str) -> NetconfReadOnlyRpcDecision:
    root = _parse_xml(xml_text)
    namespace, local_name = _split_tag(root.tag)
    if (namespace, local_name) != (NETCONF_BASE_NS, "rpc"):
        raise CiscoNetconfEvidenceError("expected NETCONF <rpc> in the base namespace")

    operations = [child for child in list(root) if isinstance(child.tag, str)]
    if len(operations) != 1:
        raise CiscoNetconfEvidenceError("NETCONF RPC must contain exactly one operation")

    operation = operations[0]
    op_namespace, op_name = _split_tag(operation.tag)
    for element in root.iter():
        _, candidate = _split_tag(element.tag)
        if candidate.lower() in _BLOCKED_OPERATION_NAMES:
            return NetconfReadOnlyRpcDecision(
                operation=op_name,
                namespace=op_namespace,
                allowed=False,
                reason=f"blocked NETCONF operation present: {candidate}",
            )
        for attr_name in element.attrib:
            attr_namespace, attr_local = _split_tag(attr_name)
            if attr_namespace == NETCONF_BASE_NS and attr_local == "operation":
                return NetconfReadOnlyRpcDecision(
                    operation=op_name,
                    namespace=op_namespace,
                    allowed=False,
                    reason="nc:operation mutation attribute is forbidden in read-only RPCs",
                )

    if (op_namespace, op_name) not in _ALLOWED_RPC_TAGS:
        return NetconfReadOnlyRpcDecision(
            operation=op_name,
            namespace=op_namespace,
            allowed=False,
            reason="operation is not in the Cisco NETCONF read-only allowlist",
        )

    if op_name in {"get", "get-config"}:
        filter_element = operation.find(f"{{{NETCONF_BASE_NS}}}filter")
        if filter_element is None or not list(filter_element):
            return NetconfReadOnlyRpcDecision(
                operation=op_name,
                namespace=op_namespace,
                allowed=False,
                reason="bounded subtree filter is required for read-only data queries",
            )
        if op_name == "get-config":
            source = operation.find(f"{{{NETCONF_BASE_NS}}}source")
            if source is None or len(list(source)) != 1:
                return NetconfReadOnlyRpcDecision(
                    operation=op_name,
                    namespace=op_namespace,
                    allowed=False,
                    reason="get-config must select exactly one datastore source",
                )
            source_namespace, source_name = _split_tag(list(source)[0].tag)
            if (source_namespace, source_name) != (NETCONF_BASE_NS, "running"):
                return NetconfReadOnlyRpcDecision(
                    operation=op_name,
                    namespace=op_namespace,
                    allowed=False,
                    reason="Cisco discovery contract permits get-config from running only",
                )

    if op_name == "get-schema":
        identifier = operation.find(f"{{{NETCONF_MONITORING_NS}}}identifier")
        if identifier is None or not (identifier.text or "").strip():
            return NetconfReadOnlyRpcDecision(
                operation=op_name,
                namespace=op_namespace,
                allowed=False,
                reason="get-schema requires a non-empty identifier",
            )

    return NetconfReadOnlyRpcDecision(
        operation=op_name,
        namespace=op_namespace,
        allowed=True,
        reason="read-only NETCONF operation accepted",
    )


def parse_schema_inventory_reply(xml_text: str) -> NetconfSchemaInventory:
    root = _parse_xml(xml_text)
    _reject_sensitive_response(root)
    namespace, local_name = _split_tag(root.tag)
    if (namespace, local_name) != (NETCONF_BASE_NS, "rpc-reply"):
        raise CiscoNetconfEvidenceError("expected NETCONF <rpc-reply>")

    schemas_parent = root.find(f".//{{{NETCONF_MONITORING_NS}}}schemas")
    if schemas_parent is None:
        raise CiscoNetconfEvidenceError("NETCONF monitoring schema inventory is missing")

    records: list[NetconfSchemaRecord] = []
    seen: set[tuple[str, str | None]] = set()
    for schema in schemas_parent.findall(f"{{{NETCONF_MONITORING_NS}}}schema"):
        identifier = (schema.findtext(f"{{{NETCONF_MONITORING_NS}}}identifier") or "").strip()
        if not identifier:
            raise CiscoNetconfEvidenceError("schema inventory entry has no identifier")
        version = (schema.findtext(f"{{{NETCONF_MONITORING_NS}}}version") or "").strip() or None
        format_value = (schema.findtext(f"{{{NETCONF_MONITORING_NS}}}format") or "").strip() or None
        namespace_value = (schema.findtext(f"{{{NETCONF_MONITORING_NS}}}namespace") or "").strip() or None
        locations = tuple(
            sorted(
                {
                    (element.text or "").strip()
                    for element in schema.findall(f"{{{NETCONF_MONITORING_NS}}}location")
                    if (element.text or "").strip()
                }
            )
        )
        key = (identifier, version)
        if key in seen:
            raise CiscoNetconfEvidenceError(
                f"duplicate NETCONF schema inventory entry: {identifier}@{version or '-'}"
            )
        seen.add(key)
        records.append(
            NetconfSchemaRecord(
                identifier=identifier,
                version=version,
                format=format_value,
                namespace=namespace_value,
                locations=locations,
            )
        )

    if not records:
        raise CiscoNetconfEvidenceError("NETCONF monitoring schema inventory is empty")
    records.sort(key=lambda item: (item.identifier, item.version or ""))
    payload = [
        {
            "identifier": item.identifier,
            "version": item.version,
            "format": item.format,
            "namespace": item.namespace,
            "locations": item.locations,
        }
        for item in records
    ]
    return NetconfSchemaInventory(
        schemas=tuple(records),
        digest_sha256=_canonical_sha256(payload),
    )


def parse_iosxe_native_version_reply(xml_text: str) -> str:
    root = _parse_xml(xml_text)
    _reject_sensitive_response(root)
    namespace, local_name = _split_tag(root.tag)
    if (namespace, local_name) != (NETCONF_BASE_NS, "rpc-reply"):
        raise CiscoNetconfEvidenceError("expected NETCONF <rpc-reply>")

    versions = [
        (element.text or "").strip()
        for element in root.findall(
            f".//{{{CISCO_NATIVE_NS}}}native/{{{CISCO_NATIVE_NS}}}version"
        )
        if (element.text or "").strip()
    ]
    unique = sorted(set(versions))
    if len(unique) != 1:
        raise CiscoNetconfEvidenceError(
            "expected exactly one Cisco-IOS-XE-native version value"
        )
    return unique[0]
