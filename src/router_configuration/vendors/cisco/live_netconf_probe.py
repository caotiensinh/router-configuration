"""Live, read-only Cisco IOS XE NETCONF probe.

Credentials are runtime-only. The probe requires an explicitly pinned SSH host
key, performs only read-only NETCONF operations, and emits minimized sanitized
evidence. It never grants production-write or physical-device authority.
"""

from __future__ import annotations

import argparse
import base64
from collections import Counter
from dataclasses import dataclass
import hashlib
import json
import os
import re
from typing import Iterable, Mapping
from xml.etree import ElementTree as ET

from .netconf_readonly import (
    CISCO_NATIVE_NS,
    NETCONF_BASE_NS,
    NETCONF_MONITORING_NS,
    MAX_NETCONF_XML_BYTES,
    CiscoNetconfEvidenceError,
    parse_schema_inventory_reply,
)
from .platforms import CiscoPlatformDecision, assess_read_only_candidate

PLATFORM_OPER_NS = "http://cisco.com/ns/yang/Cisco-IOS-XE-platform-oper"
INTERFACES_OPER_NS = "http://cisco.com/ns/yang/Cisco-IOS-XE-interfaces-oper"

_REQUIRED_SECRET_ENV = (
    "CISCO_NETCONF_HOST",
    "CISCO_NETCONF_USERNAME",
    "CISCO_NETCONF_PASSWORD",
    "CISCO_NETCONF_HOSTKEY_B64",
)
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
_MODEL_TOKEN = re.compile(
    r"\b(C(?:8000V|8200|8300|8500|9200|9300|9400|9500|9600)[A-Z0-9-]*)\b",
    re.IGNORECASE,
)


class CiscoLiveNetconfProbeError(RuntimeError):
    """Raised when live evidence cannot satisfy the fail-closed probe contract."""


@dataclass(frozen=True)
class CiscoNativeIdentity:
    hostname: str
    iosxe_version: str


@dataclass(frozen=True)
class CiscoPlatformObservation:
    model_candidates: tuple[str, ...]
    admitted_model: str | None
    platform_admission: CiscoPlatformDecision | None
    component_count: int
    component_digest_sha256: str
    serial_digest_sha256: str | None


@dataclass(frozen=True)
class CiscoInterfaceObservation:
    interface_count: int
    admin_status_counts: tuple[tuple[str, int], ...]
    oper_status_counts: tuple[tuple[str, int], ...]
    interface_digest_sha256: str


def _canonical_sha256(value: object) -> str:
    canonical = json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True)
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def _split_tag(tag: str) -> tuple[str, str]:
    if tag.startswith("{") and "}" in tag:
        namespace, local_name = tag[1:].split("}", 1)
        return namespace, local_name
    return "", tag


def _parse_secret_safe_rpc_reply(xml_text: str) -> ET.Element:
    if not isinstance(xml_text, str) or not xml_text.strip():
        raise CiscoLiveNetconfProbeError("NETCONF reply must be non-empty XML")
    encoded = xml_text.encode("utf-8")
    if len(encoded) > MAX_NETCONF_XML_BYTES:
        raise CiscoLiveNetconfProbeError("NETCONF reply exceeds bounded evidence size")
    upper = xml_text.upper()
    if "<!DOCTYPE" in upper or "<!ENTITY" in upper:
        raise CiscoLiveNetconfProbeError("DTD/entity declarations are not accepted")
    try:
        root = ET.fromstring(xml_text)
    except ET.ParseError as exc:
        raise CiscoLiveNetconfProbeError(f"invalid NETCONF reply XML: {exc}") from exc
    namespace, local_name = _split_tag(root.tag)
    if (namespace, local_name) != (NETCONF_BASE_NS, "rpc-reply"):
        raise CiscoLiveNetconfProbeError("expected NETCONF rpc-reply")
    found = sorted(
        {
            _split_tag(element.tag)[1].lower()
            for element in root.iter()
            if _split_tag(element.tag)[1].lower() in _SENSITIVE_LOCAL_NAMES
        }
    )
    if found:
        raise CiscoLiveNetconfProbeError(
            "live evidence contains sensitive fields: " + ", ".join(found)
        )
    return root


def missing_probe_inputs(env: Mapping[str, str]) -> tuple[str, ...]:
    missing = [name for name in _REQUIRED_SECRET_ENV if not (env.get(name) or "").strip()]
    return tuple(sorted(missing))


def validate_hostkey_b64(value: str) -> None:
    try:
        raw = base64.b64decode(value, validate=True)
    except Exception as exc:  # noqa: BLE001 - untrusted runtime boundary
        raise CiscoLiveNetconfProbeError("CISCO_NETCONF_HOSTKEY_B64 is not valid base64") from exc
    if len(raw) < 32:
        raise CiscoLiveNetconfProbeError("CISCO_NETCONF_HOSTKEY_B64 is implausibly short")


def parse_native_identity_reply(xml_text: str) -> CiscoNativeIdentity:
    root = _parse_secret_safe_rpc_reply(xml_text)
    native_nodes = root.findall(f".//{{{CISCO_NATIVE_NS}}}native")
    if len(native_nodes) != 1:
        raise CiscoLiveNetconfProbeError("expected exactly one Cisco native container")
    native = native_nodes[0]
    hostnames = [
        (node.text or "").strip()
        for node in native.findall(f"{{{CISCO_NATIVE_NS}}}hostname")
        if (node.text or "").strip()
    ]
    versions = [
        (node.text or "").strip()
        for node in native.findall(f"{{{CISCO_NATIVE_NS}}}version")
        if (node.text or "").strip()
    ]
    if len(set(hostnames)) != 1 or len(set(versions)) != 1:
        raise CiscoLiveNetconfProbeError(
            "native identity reply must contain exactly one hostname and IOS XE version"
        )
    return CiscoNativeIdentity(hostname=hostnames[0], iosxe_version=versions[0])


def _leaf_text(parent: ET.Element, namespace: str, name: str) -> str | None:
    node = parent.find(f"{{{namespace}}}{name}")
    if node is None:
        return None
    value = (node.text or "").strip()
    return value or None


def _extract_model_candidates(values: Iterable[str]) -> tuple[str, ...]:
    found: set[str] = set()
    for value in values:
        for match in _MODEL_TOKEN.finditer(value.upper()):
            found.add(match.group(1).upper())
    # Prefer the most specific observed product token (for example an exact
    # part number) before a shorter family token embedded in descriptive text.
    return tuple(sorted(found, key=lambda value: (-len(value), value)))


def parse_platform_oper_reply(
    xml_text: str,
    iosxe_version: str,
) -> CiscoPlatformObservation:
    root = _parse_secret_safe_rpc_reply(xml_text)
    components_parent = root.find(f".//{{{PLATFORM_OPER_NS}}}components")
    if components_parent is None:
        raise CiscoLiveNetconfProbeError("Cisco platform-oper components container is missing")
    components = components_parent.findall(f"{{{PLATFORM_OPER_NS}}}component")
    if not components:
        raise CiscoLiveNetconfProbeError("Cisco platform-oper component inventory is empty")

    normalized: list[dict[str, str | None]] = []
    model_values: list[str] = []
    serial_values: list[str] = []
    for component in components:
        record = {
            "type": _leaf_text(component, PLATFORM_OPER_NS, "type"),
            "id": _leaf_text(component, PLATFORM_OPER_NS, "id"),
            "description": _leaf_text(component, PLATFORM_OPER_NS, "description"),
            "mfg_name": _leaf_text(component, PLATFORM_OPER_NS, "mfg-name"),
            "version": _leaf_text(component, PLATFORM_OPER_NS, "version"),
            "part_no": _leaf_text(component, PLATFORM_OPER_NS, "part-no"),
            "location": _leaf_text(component, PLATFORM_OPER_NS, "location"),
        }
        serial = _leaf_text(component, PLATFORM_OPER_NS, "serial-no")
        if serial:
            serial_values.append(serial)
        normalized.append(record)
        model_values.extend(value for value in record.values() if value)

    normalized.sort(key=lambda item: json.dumps(item, sort_keys=True))
    model_candidates = _extract_model_candidates(model_values)
    admission: CiscoPlatformDecision | None = None
    admitted_model: str | None = None
    for candidate in model_candidates:
        decision = assess_read_only_candidate(candidate, iosxe_version)
        if decision.read_only_candidate:
            admission = decision
            admitted_model = candidate
            break
    if admission is None and model_candidates:
        admission = assess_read_only_candidate(model_candidates[0], iosxe_version)

    serial_digest = None
    if serial_values:
        serial_digest = _canonical_sha256(sorted(set(serial_values)))

    return CiscoPlatformObservation(
        model_candidates=model_candidates,
        admitted_model=admitted_model,
        platform_admission=admission,
        component_count=len(components),
        component_digest_sha256=_canonical_sha256(normalized),
        serial_digest_sha256=serial_digest,
    )


def parse_interfaces_oper_reply(xml_text: str) -> CiscoInterfaceObservation:
    root = _parse_secret_safe_rpc_reply(xml_text)
    interfaces_parent = root.find(f".//{{{INTERFACES_OPER_NS}}}interfaces")
    if interfaces_parent is None:
        raise CiscoLiveNetconfProbeError("Cisco interfaces-oper container is missing")
    interfaces = interfaces_parent.findall(f"{{{INTERFACES_OPER_NS}}}interface")
    if not interfaces:
        raise CiscoLiveNetconfProbeError("Cisco interfaces-oper inventory is empty")

    normalized: list[dict[str, str | None]] = []
    admin_counts: Counter[str] = Counter()
    oper_counts: Counter[str] = Counter()
    for interface in interfaces:
        record = {
            "name": _leaf_text(interface, INTERFACES_OPER_NS, "name"),
            "admin_status": _leaf_text(interface, INTERFACES_OPER_NS, "admin-status"),
            "oper_status": _leaf_text(interface, INTERFACES_OPER_NS, "oper-status"),
            "if_index": _leaf_text(interface, INTERFACES_OPER_NS, "if-index"),
            "speed": _leaf_text(interface, INTERFACES_OPER_NS, "speed"),
        }
        if not record["name"]:
            raise CiscoLiveNetconfProbeError("interfaces-oper entry is missing interface name")
        admin_counts[record["admin_status"] or "unknown"] += 1
        oper_counts[record["oper_status"] or "unknown"] += 1
        normalized.append(record)

    normalized.sort(key=lambda item: item["name"] or "")
    return CiscoInterfaceObservation(
        interface_count=len(normalized),
        admin_status_counts=tuple(sorted(admin_counts.items())),
        oper_status_counts=tuple(sorted(oper_counts.items())),
        interface_digest_sha256=_canonical_sha256(normalized),
    )


def yang_schema_has_container(schema_text: str, container_name: str) -> bool:
    if not schema_text or len(schema_text.encode("utf-8")) > MAX_NETCONF_XML_BYTES:
        return False
    pattern = re.compile(rf"\bcontainer\s+{re.escape(container_name)}\b")
    return bool(pattern.search(schema_text))


def _reply_xml(reply: object) -> str:
    value = getattr(reply, "xml", None)
    if isinstance(value, str) and value.strip():
        return value
    return str(reply)


def _schema_text(reply: object) -> str:
    for attr in ("data", "data_xml"):
        value = getattr(reply, attr, None)
        if isinstance(value, str) and value.strip():
            return value
    text = str(reply)
    if text.strip():
        return text
    raise CiscoLiveNetconfProbeError("NETCONF get-schema returned no schema text")


def _schema_inventory_filter() -> tuple[str, str]:
    return (
        "subtree",
        f'<netconf-state xmlns="{NETCONF_MONITORING_NS}"><schemas/></netconf-state>',
    )


def _native_identity_filter() -> tuple[str, str]:
    return (
        "subtree",
        f'<native xmlns="{CISCO_NATIVE_NS}"><hostname/><version/></native>',
    )


def _platform_filter() -> tuple[str, str]:
    return ("subtree", f'<components xmlns="{PLATFORM_OPER_NS}"/>')


def _interfaces_filter() -> tuple[str, str]:
    return ("subtree", f'<interfaces xmlns="{INTERFACES_OPER_NS}"/>')


def _base_evidence(source_sha: str, stage: str) -> dict:
    return {
        "schema_version": "cisco-c03-live-evidence/1",
        "source_sha": source_sha,
        "stage": stage,
        "live_target_observed": False,
        "hostkey_verified": False,
        "write_operations_performed": False,
        "production_write_authorized": False,
        "physical_device_verified": False,
        "c03_complete": False,
    }


def run_live_probe(
    *,
    host: str,
    port: int,
    username: str,
    password: str,
    hostkey_b64: str,
    source_sha: str,
    timeout: int = 20,
) -> dict:
    if not host.strip() or not username.strip() or not password:
        raise CiscoLiveNetconfProbeError("host, username, and password are required")
    if port < 1 or port > 65535:
        raise CiscoLiveNetconfProbeError("NETCONF port is outside the valid range")
    if timeout < 1 or timeout > 120:
        raise CiscoLiveNetconfProbeError("NETCONF timeout must be between 1 and 120 seconds")
    validate_hostkey_b64(hostkey_b64)

    try:
        from ncclient import manager
        import ncclient
    except ImportError as exc:
        raise CiscoLiveNetconfProbeError("ncclient is required for live NETCONF probing") from exc

    evidence = _base_evidence(source_sha, "live_probe_started")
    evidence.update(
        {
            "target_host": host,
            "target_port": port,
            "transport": "NETCONF over SSH",
            "ncclient_version": getattr(ncclient, "__version__", "unknown"),
        }
    )

    with manager.connect(
        host=host,
        port=port,
        username=username,
        password=password,
        hostkey_verify=True,
        hostkey_b64=hostkey_b64,
        allow_agent=False,
        look_for_keys=False,
        device_params={"name": "iosxe"},
        timeout=timeout,
    ) as connection:
        evidence["live_target_observed"] = True
        evidence["hostkey_verified"] = True
        capabilities = tuple(sorted(str(item) for item in connection.server_capabilities))
        if not capabilities:
            raise CiscoLiveNetconfProbeError("live NETCONF session advertised no capabilities")
        evidence["session_id"] = int(connection.session_id)
        evidence["capability_count"] = len(capabilities)
        evidence["capability_digest_sha256"] = _canonical_sha256(capabilities)

        schema_reply = connection.get(filter=_schema_inventory_filter())
        schema_inventory = parse_schema_inventory_reply(_reply_xml(schema_reply))
        evidence["schema_inventory_count"] = len(schema_inventory.schemas)
        evidence["schema_inventory_digest_sha256"] = schema_inventory.digest_sha256
        schema_names = {record.identifier for record in schema_inventory.schemas}

        required_models = {
            "Cisco-IOS-XE-native",
            "Cisco-IOS-XE-platform-oper",
            "Cisco-IOS-XE-interfaces-oper",
        }
        missing_models = sorted(required_models - schema_names)
        evidence["required_models_present"] = not missing_models
        evidence["missing_required_models"] = missing_models
        if missing_models:
            raise CiscoLiveNetconfProbeError(
                "live target does not advertise required C03 YANG models: "
                + ", ".join(missing_models)
            )

        identity_reply = connection.get_config(
            source="running",
            filter=_native_identity_filter(),
        )
        identity = parse_native_identity_reply(_reply_xml(identity_reply))
        evidence["hostname"] = identity.hostname
        evidence["iosxe_version"] = identity.iosxe_version

        platform_schema = _schema_text(connection.get_schema("Cisco-IOS-XE-platform-oper"))
        interfaces_schema = _schema_text(connection.get_schema("Cisco-IOS-XE-interfaces-oper"))
        if not yang_schema_has_container(platform_schema, "components"):
            raise CiscoLiveNetconfProbeError(
                "live platform-oper schema does not prove the expected components container"
            )
        if not yang_schema_has_container(interfaces_schema, "interfaces"):
            raise CiscoLiveNetconfProbeError(
                "live interfaces-oper schema does not prove the expected interfaces container"
            )
        evidence["platform_schema_digest_sha256"] = hashlib.sha256(
            platform_schema.encode("utf-8")
        ).hexdigest()
        evidence["interfaces_schema_digest_sha256"] = hashlib.sha256(
            interfaces_schema.encode("utf-8")
        ).hexdigest()

        platform_reply = connection.get(filter=_platform_filter())
        platform = parse_platform_oper_reply(
            _reply_xml(platform_reply),
            identity.iosxe_version,
        )
        evidence["platform_component_count"] = platform.component_count
        evidence["platform_component_digest_sha256"] = platform.component_digest_sha256
        evidence["serial_digest_sha256"] = platform.serial_digest_sha256
        evidence["model_candidates"] = list(platform.model_candidates)
        evidence["admitted_model"] = platform.admitted_model
        evidence["platform_admission_status"] = (
            platform.platform_admission.status if platform.platform_admission else "UNVERIFIED_PLATFORM"
        )
        if not platform.admitted_model or not platform.platform_admission:
            raise CiscoLiveNetconfProbeError(
                "live platform identity did not map to an admitted Cisco IOS XE family"
            )
        if not platform.platform_admission.read_only_candidate:
            raise CiscoLiveNetconfProbeError(
                f"live platform/version admission failed: {platform.platform_admission.status}"
            )

        interfaces_reply = connection.get(filter=_interfaces_filter())
        interfaces = parse_interfaces_oper_reply(_reply_xml(interfaces_reply))
        evidence["interface_count"] = interfaces.interface_count
        evidence["interface_admin_status_counts"] = dict(interfaces.admin_status_counts)
        evidence["interface_oper_status_counts"] = dict(interfaces.oper_status_counts)
        evidence["interface_digest_sha256"] = interfaces.interface_digest_sha256

    evidence["stage"] = "live_readonly_verified"
    evidence["c03_complete"] = True
    evidence["evidence_digest_sha256"] = _canonical_sha256(
        {key: value for key, value in evidence.items() if key != "evidence_digest_sha256"}
    )
    return evidence


def run_from_environment(env: Mapping[str, str] | None = None) -> tuple[dict, int]:
    environment = dict(os.environ if env is None else env)
    source_sha = (environment.get("SOURCE_SHA") or environment.get("GITHUB_SHA") or "").strip()
    if not source_sha:
        source_sha = "unknown"

    missing = missing_probe_inputs(environment)
    if missing:
        evidence = _base_evidence(source_sha, "credentials_missing")
        evidence["credentials_configured"] = False
        evidence["missing_input_count"] = len(missing)
        return evidence, 0

    port_text = (environment.get("CISCO_NETCONF_PORT") or "830").strip()
    timeout_text = (environment.get("CISCO_NETCONF_TIMEOUT") or "20").strip()
    try:
        port = int(port_text)
        timeout = int(timeout_text)
    except ValueError:
        evidence = _base_evidence(source_sha, "invalid_runtime_input")
        evidence["error_code"] = "INVALID_NUMERIC_RUNTIME_INPUT"
        return evidence, 2

    try:
        evidence = run_live_probe(
            host=environment["CISCO_NETCONF_HOST"].strip(),
            port=port,
            username=environment["CISCO_NETCONF_USERNAME"].strip(),
            password=environment["CISCO_NETCONF_PASSWORD"],
            hostkey_b64=environment["CISCO_NETCONF_HOSTKEY_B64"].strip(),
            source_sha=source_sha,
            timeout=timeout,
        )
    except (CiscoLiveNetconfProbeError, CiscoNetconfEvidenceError, OSError) as exc:
        evidence = _base_evidence(source_sha, "live_target_unavailable_or_unverified")
        evidence["error_type"] = type(exc).__name__
        evidence["error_code"] = "LIVE_C03_GATE_NOT_SATISFIED"
        return evidence, 3
    return evidence, 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Run the Cisco IOS XE read-only NETCONF C03 probe")
    parser.add_argument("--output", required=True, help="Path for sanitized JSON evidence")
    args = parser.parse_args(argv)

    evidence, exit_code = run_from_environment()
    output_dir = os.path.dirname(args.output)
    if output_dir:
        os.makedirs(output_dir, exist_ok=True)
    with open(args.output, "w", encoding="utf-8") as handle:
        json.dump(evidence, handle, indent=2, sort_keys=True)
        handle.write("\n")
    print(
        json.dumps(
            {
                "stage": evidence["stage"],
                "c03_complete": evidence["c03_complete"],
                "source_sha": evidence["source_sha"],
            },
            sort_keys=True,
        )
    )
    return exit_code


if __name__ == "__main__":
    raise SystemExit(main())
