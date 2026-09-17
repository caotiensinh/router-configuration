"""Conservative Yamaha RTX3510 operational-state normalization.

Only surfaces whose output semantics are source-bound are parsed. LAN status
outputs are intentionally retained as digests with operational state ``unknown``
until an exact, version-bound parser contract is approved.
"""

from __future__ import annotations

from dataclasses import dataclass
import hashlib
import ipaddress
import json
import re
from typing import Mapping

from .readonly import YamahaReadOnlyEvidenceError, parse_environment_identity


YAMAHA_NORMALIZED_STATE_SCHEMA = "yamaha-rtx3510-normalized-state/1"
_REQUIRED_LAN_COMMANDS = tuple(f"show status lan{index}" for index in range(1, 5))
_ROUTE_SOURCE_IDS = (
    "YAMAHA-RTX-CMDREF",
    "YAMAHA-RTX3510-USERGUIDE",
)


class YamahaNormalizedStateError(ValueError):
    """Raised when Yamaha normalized state cannot be derived safely."""


@dataclass(frozen=True)
class YamahaIPv4Route:
    destination: str
    gateway: str | None
    interface: str
    route_type: str
    additional_info: str | None
    active: bool = True


def _validate_destination(value: str) -> str:
    if value == "default":
        return value
    try:
        network = ipaddress.ip_network(value, strict=False)
    except ValueError as exc:
        raise YamahaNormalizedStateError(
            f"unrecognized Yamaha IPv4 route destination: {value}"
        ) from exc
    if network.version != 4:
        raise YamahaNormalizedStateError(
            f"non-IPv4 destination in Yamaha IPv4 route table: {value}"
        )
    return str(network)


def parse_ipv4_routes(output: str) -> tuple[YamahaIPv4Route, ...]:
    """Parse the documented ``show ip route`` table conservatively.

    Yamaha documents the table as destination, gateway, interface, route type,
    followed by optional protocol-specific information. Plain ``show ip route``
    represents the current IPv4 routing table; hidden static routes belong to
    the separate ``detail`` form and are intentionally outside this parser.
    """

    if not isinstance(output, str) or not output.strip():
        raise YamahaNormalizedStateError("show ip route output is empty")

    routes: list[YamahaIPv4Route] = []
    for raw_line in output.splitlines():
        line = raw_line.strip()
        if not line:
            continue
        if line.startswith("#") and "show ip route" in line:
            continue
        if "宛先ネットワーク" in line and "ゲートウェイ" in line:
            continue

        fields = re.split(r"\s+", line)
        if len(fields) < 4:
            raise YamahaNormalizedStateError(
                f"unrecognized Yamaha show ip route row: {line}"
            )

        destination = _validate_destination(fields[0])
        gateway = None if fields[1] == "-" else fields[1]
        interface = fields[2]
        route_type = fields[3]
        additional_info = " ".join(fields[4:]) or None
        if not interface or not route_type:
            raise YamahaNormalizedStateError(
                f"incomplete Yamaha show ip route row: {line}"
            )
        routes.append(
            YamahaIPv4Route(
                destination=destination,
                gateway=gateway,
                interface=interface,
                route_type=route_type,
                additional_info=additional_info,
            )
        )

    if not routes:
        raise YamahaNormalizedStateError("show ip route contained no route rows")

    routes.sort(
        key=lambda item: (
            item.destination,
            item.interface,
            item.gateway or "",
            item.route_type,
            item.additional_info or "",
        )
    )
    return tuple(routes)


def build_normalized_state(
    *,
    environment_output: str,
    route_output: str,
    lan_outputs: Mapping[str, str],
) -> dict:
    """Build a deterministic partial state without inventing LAN link semantics."""

    try:
        identity = parse_environment_identity(environment_output)
    except YamahaReadOnlyEvidenceError as exc:
        raise YamahaNormalizedStateError(str(exc)) from exc

    routes = parse_ipv4_routes(route_output)
    interfaces = []
    for index, command in enumerate(_REQUIRED_LAN_COMMANDS, start=1):
        output = lan_outputs.get(command)
        if not isinstance(output, str) or not output.strip():
            raise YamahaNormalizedStateError(
                f"missing Yamaha LAN observation: {command}"
            )
        interfaces.append(
            {
                "name": f"lan{index}",
                "operational_state": "unknown",
                "parsed_link_state": False,
                "observation_command": command,
                "observation_sha256": hashlib.sha256(
                    output.encode("utf-8")
                ).hexdigest(),
            }
        )

    route_records = [
        {
            "destination": route.destination,
            "gateway": route.gateway,
            "interface": route.interface,
            "route_type": route.route_type,
            "additional_info": route.additional_info,
            "active": route.active,
        }
        for route in routes
    ]

    state = {
        "schema_version": YAMAHA_NORMALIZED_STATE_SCHEMA,
        "device": {
            "vendor": "Yamaha",
            "model": identity.model,
            "firmware": identity.firmware,
        },
        "interfaces": interfaces,
        "ipv4_routes": route_records,
        "source": {
            "route_command": "show ip route",
            "route_source_ids": list(_ROUTE_SOURCE_IDS),
            "capture_source": "caller_supplied",
            "raw_outputs_embedded": False,
            "transport_verified": False,
            "least_privilege_verified": False,
            "live_device_verified": False,
            "physical_device_verified": False,
            "production_write_authorized": False,
            "missing_surfaces": [
                "interface_link_state_parser",
                "interface_addresses",
                "routing_tables",
                "security",
                "vpn",
                "qos",
            ],
        },
    }
    canonical = json.dumps(state, sort_keys=True, separators=(",", ":"))
    state["record_sha256"] = hashlib.sha256(canonical.encode("utf-8")).hexdigest()
    validate_normalized_state(state)
    return state


def validate_normalized_state(state: Mapping[str, object]) -> None:
    if state.get("schema_version") != YAMAHA_NORMALIZED_STATE_SCHEMA:
        raise YamahaNormalizedStateError("unsupported Yamaha normalized-state schema")

    device = state.get("device")
    if not isinstance(device, Mapping):
        raise YamahaNormalizedStateError("Yamaha normalized device is missing")
    if (
        device.get("vendor") != "Yamaha"
        or device.get("model") != "RTX3510"
        or device.get("firmware") != "23.01.03"
    ):
        raise YamahaNormalizedStateError("Yamaha normalized identity mismatch")

    interfaces = state.get("interfaces")
    if not isinstance(interfaces, list) or len(interfaces) != 4:
        raise YamahaNormalizedStateError("Yamaha normalized interfaces must be LAN1-LAN4")
    expected_names = ["lan1", "lan2", "lan3", "lan4"]
    if [item.get("name") for item in interfaces if isinstance(item, Mapping)] != expected_names:
        raise YamahaNormalizedStateError("Yamaha normalized LAN inventory mismatch")
    for item in interfaces:
        if not isinstance(item, Mapping):
            raise YamahaNormalizedStateError("invalid Yamaha normalized interface")
        if item.get("operational_state") != "unknown" or item.get("parsed_link_state") is not False:
            raise YamahaNormalizedStateError("Yamaha LAN link state must remain unparsed")
        digest = item.get("observation_sha256")
        if not isinstance(digest, str) or re.fullmatch(r"[0-9a-f]{64}", digest) is None:
            raise YamahaNormalizedStateError("invalid Yamaha LAN observation digest")

    routes = state.get("ipv4_routes")
    if not isinstance(routes, list) or not routes:
        raise YamahaNormalizedStateError("Yamaha normalized IPv4 routes are missing")
    for route in routes:
        if not isinstance(route, Mapping):
            raise YamahaNormalizedStateError("invalid Yamaha normalized route")
        _validate_destination(str(route.get("destination", "")))
        if not str(route.get("interface", "")).strip():
            raise YamahaNormalizedStateError("Yamaha normalized route interface is empty")
        if not str(route.get("route_type", "")).strip():
            raise YamahaNormalizedStateError("Yamaha normalized route type is empty")
        if route.get("active") is not True:
            raise YamahaNormalizedStateError("plain show ip route entries must remain active")

    source = state.get("source")
    if not isinstance(source, Mapping):
        raise YamahaNormalizedStateError("Yamaha normalized source metadata is missing")
    if source.get("raw_outputs_embedded") is not False:
        raise YamahaNormalizedStateError("raw Yamaha outputs must not be embedded")
    for key in (
        "transport_verified",
        "least_privilege_verified",
        "live_device_verified",
        "physical_device_verified",
        "production_write_authorized",
    ):
        if source.get(key) is not False:
            raise YamahaNormalizedStateError(f"Yamaha normalized state overclaims {key}")
    missing = source.get("missing_surfaces")
    if not isinstance(missing, list) or "interface_link_state_parser" not in missing:
        raise YamahaNormalizedStateError("Yamaha missing-surface boundary was removed")

    supplied_digest = state.get("record_sha256")
    if not isinstance(supplied_digest, str) or re.fullmatch(r"[0-9a-f]{64}", supplied_digest) is None:
        raise YamahaNormalizedStateError("invalid Yamaha normalized-state digest")
    payload = dict(state)
    payload.pop("record_sha256", None)
    canonical = json.dumps(payload, sort_keys=True, separators=(",", ":"))
    expected = hashlib.sha256(canonical.encode("utf-8")).hexdigest()
    if supplied_digest != expected:
        raise YamahaNormalizedStateError("Yamaha normalized-state digest mismatch")
