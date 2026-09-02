from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Mapping

from .routeros_capabilities import assess_routeros_capabilities
from .routeros_state_contract import validate_routeros_state

NETWORK_STATE_SCHEMA = "network-state/1"

_REQUIRED_TOP_LEVEL = {
    "schema_version",
    "device",
    "interfaces",
    "addresses",
    "routes",
    "routing_tables",
    "security",
    "vpn",
    "qos",
    "source",
}


@dataclass(frozen=True)
class NetworkStateValidationResult:
    errors: tuple[str, ...]
    warnings: tuple[str, ...] = ()

    @property
    def ok(self) -> bool:
        return not self.errors


def _bool(value: Any, *, default: bool = False) -> bool:
    if isinstance(value, bool):
        return value
    if isinstance(value, str):
        lowered = value.strip().lower()
        if lowered == "true":
            return True
        if lowered == "false":
            return False
    return default


def _int_or_none(value: Any) -> int | None:
    if value is None or value == "":
        return None
    try:
        return int(value)
    except (TypeError, ValueError):
        return None


def _copy_selected(record: Mapping[str, Any], keys: tuple[str, ...]) -> dict[str, Any]:
    return {key: record[key] for key in keys if key in record}


def routeros_to_network_state(state: Mapping[str, Any]) -> dict[str, Any]:
    """Map validated RouterOS discovery state into the vendor-neutral core schema.

    Vendor record identifiers are retained only as `source_ref` for audit/diff
    traceability. Policy decisions must use the normalized fields, not source_ref.
    """

    validation = validate_routeros_state(state)
    if not validation.ok:
        raise ValueError(
            "RouterOS state does not satisfy routeros-state/1: "
            + "; ".join(validation.errors)
        )

    platform = state["platform"]
    capabilities = assess_routeros_capabilities(state)

    interfaces = []
    for item in state["interfaces"]:
        interfaces.append(
            {
                "name": str(item.get("name", "")),
                "kind": str(item.get("type", "unknown")),
                "enabled": not _bool(item.get("disabled"), default=False),
                "operational": _bool(item.get("running"), default=False),
                "source_ref": item.get(".id"),
            }
        )
    interfaces.sort(key=lambda item: (item["name"], str(item.get("source_ref") or "")))

    addresses = []
    for item in state["ip_addresses"]:
        addresses.append(
            {
                "address": str(item.get("address", "")),
                "interface": str(item.get("interface", "")),
                "dynamic": _bool(item.get("dynamic"), default=False),
                "source_ref": item.get(".id"),
            }
        )
    addresses.sort(key=lambda item: (item["interface"], item["address"]))

    routes = []
    for item in state["ip_routes"]:
        routes.append(
            {
                "destination": str(item.get("dst-address", "")),
                "gateway": item.get("gateway"),
                "table": str(item.get("routing-table", "main")),
                "distance": _int_or_none(item.get("distance")),
                "active": _bool(item.get("active"), default=False),
                "dynamic": _bool(item.get("dynamic"), default=False),
                "source_ref": item.get(".id"),
            }
        )
    routes.sort(
        key=lambda item: (
            item["table"],
            item["destination"],
            str(item.get("gateway") or ""),
            item["distance"] if item["distance"] is not None else -1,
        )
    )

    routing_tables = []
    for item in state["routing_tables"]:
        routing_tables.append(
            {
                "name": str(item.get("name", "")),
                "fib": _bool(item.get("fib"), default=False),
                "source_ref": item.get(".id"),
            }
        )
    routing_tables.sort(key=lambda item: item["name"])

    firewall_filter = []
    for item in state["firewall"]["filter"]:
        firewall_filter.append(
            {
                "chain": str(item.get("chain", "")),
                "action": str(item.get("action", "")),
                "enabled": not _bool(item.get("disabled"), default=False),
                "match": _copy_selected(
                    item,
                    (
                        "protocol",
                        "src-address",
                        "dst-address",
                        "src-port",
                        "dst-port",
                        "in-interface",
                        "out-interface",
                        "connection-state",
                    ),
                ),
                "source_ref": item.get(".id"),
            }
        )
    firewall_filter.sort(
        key=lambda item: (
            item["chain"],
            item["action"],
            str(item.get("source_ref") or ""),
        )
    )

    firewall_nat = []
    for item in state["firewall"]["nat"]:
        firewall_nat.append(
            {
                "chain": str(item.get("chain", "")),
                "action": str(item.get("action", "")),
                "enabled": not _bool(item.get("disabled"), default=False),
                "match": _copy_selected(
                    item,
                    (
                        "protocol",
                        "src-address",
                        "dst-address",
                        "src-port",
                        "dst-port",
                        "in-interface",
                        "out-interface",
                    ),
                ),
                "source_ref": item.get(".id"),
            }
        )
    firewall_nat.sort(
        key=lambda item: (
            item["chain"],
            item["action"],
            str(item.get("source_ref") or ""),
        )
    )

    wg_interfaces = []
    for item in state["wireguard"]["interfaces"]:
        wg_interfaces.append(
            {
                "name": str(item.get("name", "")),
                "listen_port": _int_or_none(item.get("listen-port")),
                "public_key": item.get("public-key"),
                "enabled": not _bool(item.get("disabled"), default=False),
                "source_ref": item.get(".id"),
            }
        )
    wg_interfaces.sort(key=lambda item: item["name"])

    wg_peers = []
    for item in state["wireguard"]["peers"]:
        wg_peers.append(
            {
                "interface": str(item.get("interface", "")),
                "public_key": item.get("public-key"),
                "allowed_addresses": item.get("allowed-address"),
                "endpoint_address": item.get("endpoint-address"),
                "endpoint_port": _int_or_none(item.get("endpoint-port")),
                "enabled": not _bool(item.get("disabled"), default=False),
                "source_ref": item.get(".id"),
            }
        )
    wg_peers.sort(
        key=lambda item: (
            item["interface"],
            str(item.get("public_key") or ""),
        )
    )

    simple_queues = []
    for item in state["qos"]["simple_queues"]:
        simple_queues.append(
            {
                "name": str(item.get("name", "")),
                "target": item.get("target"),
                "max_limit": item.get("max-limit"),
                "enabled": not _bool(item.get("disabled"), default=False),
                "source_ref": item.get(".id"),
            }
        )
    simple_queues.sort(key=lambda item: item["name"])

    queue_tree = []
    for item in state["qos"]["queue_tree"]:
        queue_tree.append(
            {
                "name": str(item.get("name", "")),
                "parent": item.get("parent"),
                "packet_mark": item.get("packet-mark"),
                "max_limit": item.get("max-limit"),
                "enabled": not _bool(item.get("disabled"), default=False),
                "source_ref": item.get(".id"),
            }
        )
    queue_tree.sort(key=lambda item: item["name"])

    result = {
        "schema_version": NETWORK_STATE_SCHEMA,
        "device": {
            "vendor": "mikrotik",
            "identity": platform.get("identity"),
            "model": platform.get("board_name"),
            "firmware_version": platform.get("version"),
            "architecture": platform.get("architecture"),
        },
        "interfaces": interfaces,
        "addresses": addresses,
        "routes": routes,
        "routing_tables": routing_tables,
        "security": {
            "firewall_filter": firewall_filter,
            "nat": firewall_nat,
        },
        "vpn": {
            "wireguard": {
                "interfaces": wg_interfaces,
                "peers": wg_peers,
            }
        },
        "qos": {
            "simple_queues": simple_queues,
            "queue_tree": queue_tree,
        },
        "source": {
            "vendor_schema": state["schema_version"],
            "missing_surfaces": list(state["missing_surfaces"]),
            "capabilities": dict(capabilities.capabilities),
        },
    }

    normalized_validation = validate_network_state(result)
    if not normalized_validation.ok:
        raise RuntimeError(
            "generated network-state/1 is invalid: "
            + "; ".join(normalized_validation.errors)
        )
    return result


def _require_list_of_objects(
    state: Mapping[str, Any], key: str, errors: list[str]
) -> None:
    value = state.get(key)
    if not isinstance(value, list):
        errors.append(f"{key} must be a list")
        return
    if not all(isinstance(item, Mapping) for item in value):
        errors.append(f"{key} entries must be objects")


def validate_network_state(state: Mapping[str, Any]) -> NetworkStateValidationResult:
    errors: list[str] = []
    warnings: list[str] = []

    missing = sorted(_REQUIRED_TOP_LEVEL - set(state))
    unknown = sorted(set(state) - _REQUIRED_TOP_LEVEL)
    if missing:
        errors.append("missing network-state fields: " + ", ".join(missing))
    if unknown:
        errors.append("unknown network-state fields: " + ", ".join(unknown))
    if state.get("schema_version") != NETWORK_STATE_SCHEMA:
        errors.append(f"schema_version must be {NETWORK_STATE_SCHEMA}")

    device = state.get("device")
    if not isinstance(device, Mapping):
        errors.append("device must be an object")
    else:
        allowed = {"vendor", "identity", "model", "firmware_version", "architecture"}
        extra = sorted(set(device) - allowed)
        if extra:
            errors.append("unknown device fields: " + ", ".join(extra))
        if not str(device.get("vendor", "")).strip():
            errors.append("device.vendor must not be empty")
        if not str(device.get("model", "")).strip():
            warnings.append("device.model is empty")

    for key in ("interfaces", "addresses", "routes", "routing_tables"):
        _require_list_of_objects(state, key, errors)

    for key in ("security", "vpn", "qos", "source"):
        if not isinstance(state.get(key), Mapping):
            errors.append(f"{key} must be an object")

    source = state.get("source")
    if isinstance(source, Mapping):
        if not str(source.get("vendor_schema", "")).strip():
            errors.append("source.vendor_schema must not be empty")
        missing_surfaces = source.get("missing_surfaces")
        if not isinstance(missing_surfaces, list) or not all(
            isinstance(item, str) for item in missing_surfaces
        ):
            errors.append("source.missing_surfaces must be a list of strings")

    return NetworkStateValidationResult(tuple(errors), tuple(warnings))
