from __future__ import annotations

import hashlib
import hmac
import ipaddress
import json
import math
import re
from dataclasses import dataclass
from typing import Any, Mapping, Sequence

from .device_backend import EvidenceClass
from .network_sandbox_acceptance import NETWORK_SANDBOX_REPOSITORY


REQUEST_SCHEMA = "network-sandbox-scenario-request/1"
COMPILED_SCHEMA = "network-sandbox-compiled-scenario/1"
NETWORK_SANDBOX_SCENARIO_SCHEMA_VERSION = 1

_SHA40 = re.compile(r"^[0-9a-f]{40}$")
_ALLOWED_NODE_KINDS = frozenset({"host", "router", "switch", "internet"})
_ALLOWED_ROUTED_KINDS = frozenset({"host", "router", "internet"})
_ALLOWED_PROTOCOLS = frozenset({"icmp", "tcp", "udp"})
_ALLOWED_EXPECTATIONS = frozenset({"reachable", "blocked"})
_ALLOWED_NODE_KEYS = frozenset({"name", "kind", "interfaces", "routes"})
_ALLOWED_INTERFACE_KEYS = frozenset(
    {"name", "address", "mode", "access_vlan", "allowed_vlans", "native_vlan"}
)
_ALLOWED_ROUTE_KEYS = frozenset(
    {"destination", "out_interface", "next_hop", "metric"}
)
_ALLOWED_LINK_KEYS = frozenset({"name", "endpoints", "up", "latency_ms", "loss_pct"})
_ALLOWED_TEST_KEYS = frozenset(
    {"name", "src_node", "dst_ip", "protocol", "dst_port", "src_ip", "expect"}
)
_ALLOWED_REQUEST_KEYS = frozenset(
    {
        "schema_version",
        "network_sandbox_sha",
        "scenario_id",
        "nodes",
        "links",
        "tests",
        "warmup_ms",
    }
)


class NetworkSandboxScenarioCompileError(ValueError):
    """Raised when a hardware-free sandbox scenario request is unsafe or invalid."""


@dataclass(frozen=True)
class CompiledNetworkSandboxScenario:
    payload: Mapping[str, Any]

    def as_dict(self) -> dict[str, Any]:
        return dict(self.payload)

    @property
    def scenario(self) -> Mapping[str, Any]:
        value = self.payload.get("scenario")
        if not isinstance(value, Mapping):
            raise NetworkSandboxScenarioCompileError("compiled scenario payload is missing")
        return value


def _canonical_sha256(value: Any) -> str:
    encoded = json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        default=str,
    ).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def _single_line(value: object, label: str) -> str:
    text = str(value or "").strip()
    if not text or any(character in text for character in ("\n", "\r", "\x00")):
        raise NetworkSandboxScenarioCompileError(
            f"{label} must be a non-empty single-line value"
        )
    return text


def _sha40(value: object, label: str) -> str:
    text = str(value or "").strip().lower()
    if not _SHA40.fullmatch(text):
        raise NetworkSandboxScenarioCompileError(
            f"{label} must be a lowercase 40-character git SHA"
        )
    return text


def _object(value: object, label: str) -> Mapping[str, Any]:
    if not isinstance(value, Mapping):
        raise NetworkSandboxScenarioCompileError(f"{label} must be an object")
    return value


def _array(value: object, label: str) -> Sequence[Any]:
    if not isinstance(value, Sequence) or isinstance(value, (str, bytes, bytearray)):
        raise NetworkSandboxScenarioCompileError(f"{label} must be an array")
    return value


def _reject_unknown(
    value: Mapping[str, Any],
    *,
    allowed: frozenset[str],
    label: str,
) -> None:
    unknown = sorted(set(value) - allowed)
    if unknown:
        raise NetworkSandboxScenarioCompileError(
            f"{label} has unsupported fields: {unknown}"
        )


def _ipv4_interface(value: object, label: str) -> str:
    text = _single_line(value, label)
    try:
        parsed = ipaddress.ip_interface(text)
    except ValueError as exc:
        raise NetworkSandboxScenarioCompileError(
            f"{label} must be a valid IP interface"
        ) from exc
    if parsed.version != 4:
        raise NetworkSandboxScenarioCompileError(f"{label} must be IPv4")
    return str(parsed)


def _ipv4_network(value: object, label: str) -> str:
    text = _single_line(value, label)
    try:
        parsed = ipaddress.ip_network(text, strict=False)
    except ValueError as exc:
        raise NetworkSandboxScenarioCompileError(
            f"{label} must be a valid IPv4 network"
        ) from exc
    if parsed.version != 4:
        raise NetworkSandboxScenarioCompileError(f"{label} must be IPv4")
    return str(parsed)


def _ipv4_address(value: object, label: str) -> str:
    text = _single_line(value, label)
    try:
        parsed = ipaddress.ip_address(text)
    except ValueError as exc:
        raise NetworkSandboxScenarioCompileError(
            f"{label} must be a valid IPv4 address"
        ) from exc
    if parsed.version != 4:
        raise NetworkSandboxScenarioCompileError(f"{label} must be IPv4")
    return str(parsed)


def _vlan(value: object, label: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or not 1 <= value <= 4094:
        raise NetworkSandboxScenarioCompileError(
            f"{label} must be an integer from 1 through 4094"
        )
    return value


def _finite_nonnegative(value: object, label: str) -> float:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise NetworkSandboxScenarioCompileError(
            f"{label} must be a finite number >= 0"
        )
    result = float(value)
    if not math.isfinite(result) or result < 0:
        raise NetworkSandboxScenarioCompileError(
            f"{label} must be a finite number >= 0"
        )
    return result


def _compile_interface(
    raw: Mapping[str, Any],
    *,
    node_kind: str,
    node_name: str,
    index: int,
) -> dict[str, Any]:
    label = f"nodes[{node_name}].interfaces[{index}]"
    _reject_unknown(raw, allowed=_ALLOWED_INTERFACE_KEYS, label=label)
    name = _single_line(raw.get("name"), f"{label}.name")

    if node_kind == "switch":
        mode = _single_line(raw.get("mode"), f"{label}.mode").lower()
        if mode not in {"access", "trunk"}:
            raise NetworkSandboxScenarioCompileError(
                f"{label}.mode must be access or trunk for switch nodes"
            )
        if raw.get("address") not in (None, ""):
            raise NetworkSandboxScenarioCompileError(
                f"{label}.address is not admitted for switch interfaces in compiler v1"
            )

        access_vlan = raw.get("access_vlan")
        native_vlan = raw.get("native_vlan")
        allowed_raw = raw.get("allowed_vlans", [])
        allowed_values = _array(allowed_raw, f"{label}.allowed_vlans")
        allowed = sorted({_vlan(item, f"{label}.allowed_vlans[]") for item in allowed_values})

        compiled: dict[str, Any] = {"name": name, "mode": mode}
        if mode == "access":
            if access_vlan is None:
                raise NetworkSandboxScenarioCompileError(
                    f"{label}.access_vlan is required for access mode"
                )
            if native_vlan is not None or allowed:
                raise NetworkSandboxScenarioCompileError(
                    f"{label} access mode cannot define native_vlan or allowed_vlans"
                )
            compiled["access_vlan"] = _vlan(access_vlan, f"{label}.access_vlan")
            return compiled

        if access_vlan is not None:
            raise NetworkSandboxScenarioCompileError(
                f"{label} trunk mode cannot define access_vlan"
            )
        if native_vlan is not None:
            compiled["native_vlan"] = _vlan(native_vlan, f"{label}.native_vlan")
        if allowed:
            compiled["allowed_vlans"] = allowed
        return compiled

    if node_kind not in _ALLOWED_ROUTED_KINDS:
        raise NetworkSandboxScenarioCompileError(
            f"unsupported routed node kind: {node_kind}"
        )
    if raw.get("mode") not in (None, "", "routed"):
        raise NetworkSandboxScenarioCompileError(
            f"{label}.mode must be routed for {node_kind} nodes"
        )
    for forbidden in ("access_vlan", "allowed_vlans", "native_vlan"):
        if raw.get(forbidden) not in (None, "", []):
            raise NetworkSandboxScenarioCompileError(
                f"{label}.{forbidden} is only admitted for switch interfaces"
            )

    compiled = {"name": name}
    if raw.get("address") not in (None, ""):
        compiled["address"] = _ipv4_interface(raw.get("address"), f"{label}.address")
    return compiled


def _compile_route(
    raw: Mapping[str, Any],
    *,
    node_name: str,
    interface_names: frozenset[str],
    index: int,
) -> dict[str, Any]:
    label = f"nodes[{node_name}].routes[{index}]"
    _reject_unknown(raw, allowed=_ALLOWED_ROUTE_KEYS, label=label)
    destination = _ipv4_network(raw.get("destination"), f"{label}.destination")
    out_interface = _single_line(raw.get("out_interface"), f"{label}.out_interface")
    if out_interface not in interface_names:
        raise NetworkSandboxScenarioCompileError(
            f"{label}.out_interface references unknown interface: {out_interface}"
        )

    next_hop = raw.get("next_hop")
    metric = raw.get("metric", 1)
    if isinstance(metric, bool) or not isinstance(metric, int) or metric < 1:
        raise NetworkSandboxScenarioCompileError(
            f"{label}.metric must be a positive integer"
        )

    compiled: dict[str, Any] = {
        "destination": destination,
        "out_interface": out_interface,
        "metric": metric,
    }
    if next_hop not in (None, ""):
        compiled["next_hop"] = _ipv4_address(next_hop, f"{label}.next_hop")
    return compiled


def _compile_node(raw: Mapping[str, Any], index: int) -> dict[str, Any]:
    label = f"nodes[{index}]"
    _reject_unknown(raw, allowed=_ALLOWED_NODE_KEYS, label=label)
    name = _single_line(raw.get("name"), f"{label}.name")
    kind = _single_line(raw.get("kind"), f"{label}.kind").lower()
    if kind not in _ALLOWED_NODE_KINDS:
        raise NetworkSandboxScenarioCompileError(
            f"{label}.kind must be one of {sorted(_ALLOWED_NODE_KINDS)}"
        )

    interfaces_raw = _array(raw.get("interfaces", []), f"{label}.interfaces")
    interfaces: list[dict[str, Any]] = []
    names: set[str] = set()
    for interface_index, item in enumerate(interfaces_raw):
        interface = _compile_interface(
            _object(item, f"{label}.interfaces[{interface_index}]"),
            node_kind=kind,
            node_name=name,
            index=interface_index,
        )
        if interface["name"] in names:
            raise NetworkSandboxScenarioCompileError(
                f"duplicate interface on node {name}: {interface['name']}"
            )
        names.add(interface["name"])
        interfaces.append(interface)

    routes_raw = _array(raw.get("routes", []), f"{label}.routes")
    if kind == "switch" and routes_raw:
        raise NetworkSandboxScenarioCompileError(
            f"{label}.routes are not admitted for switch nodes in compiler v1"
        )
    routes = [
        _compile_route(
            _object(item, f"{label}.routes[{route_index}]"),
            node_name=name,
            interface_names=frozenset(names),
            index=route_index,
        )
        for route_index, item in enumerate(routes_raw)
    ]

    interfaces.sort(key=lambda item: item["name"])
    routes.sort(
        key=lambda item: (
            item["destination"],
            item["out_interface"],
            item.get("next_hop", ""),
            item["metric"],
        )
    )
    compiled: dict[str, Any] = {
        "name": name,
        "kind": kind,
        "interfaces": interfaces,
    }
    if routes:
        compiled["routes"] = routes
    return compiled


def _endpoint_inventory(nodes: Sequence[Mapping[str, Any]]) -> frozenset[str]:
    endpoints: set[str] = set()
    for node in nodes:
        name = str(node["name"])
        interfaces = node.get("interfaces", [])
        assert isinstance(interfaces, list)
        for interface in interfaces:
            assert isinstance(interface, Mapping)
            endpoints.add(f"{name}:{interface['name']}")
    return frozenset(endpoints)


def _compile_link(
    raw: Mapping[str, Any],
    *,
    valid_endpoints: frozenset[str],
    index: int,
) -> dict[str, Any]:
    label = f"links[{index}]"
    _reject_unknown(raw, allowed=_ALLOWED_LINK_KEYS, label=label)
    name = _single_line(raw.get("name"), f"{label}.name")
    endpoints_raw = _array(raw.get("endpoints"), f"{label}.endpoints")
    if len(endpoints_raw) != 2:
        raise NetworkSandboxScenarioCompileError(
            f"{label}.endpoints must contain exactly two endpoints"
        )
    endpoints = [
        _single_line(item, f"{label}.endpoints[]") for item in endpoints_raw
    ]
    if endpoints[0] == endpoints[1]:
        raise NetworkSandboxScenarioCompileError(
            f"{label}.endpoints must reference two different interfaces"
        )
    for endpoint in endpoints:
        if endpoint not in valid_endpoints:
            raise NetworkSandboxScenarioCompileError(
                f"{label} references unknown endpoint: {endpoint}"
            )

    up = raw.get("up", True)
    if type(up) is not bool:
        raise NetworkSandboxScenarioCompileError(f"{label}.up must be boolean")
    latency = _finite_nonnegative(raw.get("latency_ms", 0.0), f"{label}.latency_ms")
    loss = _finite_nonnegative(raw.get("loss_pct", 0.0), f"{label}.loss_pct")
    if loss > 100:
        raise NetworkSandboxScenarioCompileError(
            f"{label}.loss_pct must be between 0 and 100"
        )

    compiled: dict[str, Any] = {
        "name": name,
        "endpoints": endpoints,
    }
    if not up:
        compiled["up"] = False
    if latency:
        compiled["latency_ms"] = latency
    if loss:
        compiled["loss_pct"] = loss
    return compiled


def _compile_test(
    raw: Mapping[str, Any],
    *,
    node_kinds: Mapping[str, str],
    index: int,
) -> dict[str, Any]:
    label = f"tests[{index}]"
    _reject_unknown(raw, allowed=_ALLOWED_TEST_KEYS, label=label)
    name = _single_line(raw.get("name"), f"{label}.name")
    src_node = _single_line(raw.get("src_node"), f"{label}.src_node")
    if src_node not in node_kinds:
        raise NetworkSandboxScenarioCompileError(
            f"{label}.src_node references unknown node: {src_node}"
        )
    if node_kinds[src_node] == "switch":
        raise NetworkSandboxScenarioCompileError(
            f"{label}.src_node cannot be a switch in Network Sandbox compiler v1"
        )
    destination = _ipv4_address(raw.get("dst_ip"), f"{label}.dst_ip")
    protocol = str(raw.get("protocol", "icmp")).strip().lower()
    if protocol not in _ALLOWED_PROTOCOLS:
        raise NetworkSandboxScenarioCompileError(
            f"{label}.protocol must be one of {sorted(_ALLOWED_PROTOCOLS)}"
        )
    expectation = str(raw.get("expect", "reachable")).strip().lower()
    if expectation not in _ALLOWED_EXPECTATIONS:
        raise NetworkSandboxScenarioCompileError(
            f"{label}.expect must be reachable or blocked"
        )

    compiled: dict[str, Any] = {
        "name": name,
        "src_node": src_node,
        "dst_ip": destination,
        "protocol": protocol,
        "expect": expectation,
    }
    src_ip = raw.get("src_ip")
    if src_ip not in (None, ""):
        compiled["src_ip"] = _ipv4_address(src_ip, f"{label}.src_ip")
    dst_port = raw.get("dst_port")
    if dst_port is not None:
        if protocol not in {"tcp", "udp"}:
            raise NetworkSandboxScenarioCompileError(
                f"{label}.dst_port is only valid for tcp or udp"
            )
        if isinstance(dst_port, bool) or not isinstance(dst_port, int) or not 1 <= dst_port <= 65535:
            raise NetworkSandboxScenarioCompileError(
                f"{label}.dst_port must be an integer from 1 through 65535"
            )
        compiled["dst_port"] = dst_port
    return compiled


def _validate_request_shape(request: Mapping[str, Any]) -> None:
    _reject_unknown(request, allowed=_ALLOWED_REQUEST_KEYS, label="request")
    if request.get("schema_version") != REQUEST_SCHEMA:
        raise NetworkSandboxScenarioCompileError(
            f"request.schema_version must be {REQUEST_SCHEMA}"
        )


def compile_network_sandbox_scenario(
    request: Mapping[str, Any],
) -> CompiledNetworkSandboxScenario:
    """Compile a bounded vendor-neutral request into Network Sandbox scenario v1.

    Compiler v1 deliberately covers topology, IPv4 static routing, link state /
    impairment and reachability assertions only. Vendor CLI/API semantics,
    credentials, production transport, and hardware claims are outside scope.
    """

    if not isinstance(request, Mapping):
        raise NetworkSandboxScenarioCompileError("request must be an object")
    _validate_request_shape(request)

    sandbox_sha = _sha40(request.get("network_sandbox_sha"), "network_sandbox_sha")
    scenario_id = _single_line(request.get("scenario_id"), "scenario_id")

    nodes_raw = _array(request.get("nodes"), "nodes")
    if not nodes_raw:
        raise NetworkSandboxScenarioCompileError("nodes must not be empty")
    nodes = [
        _compile_node(_object(item, f"nodes[{index}]"), index)
        for index, item in enumerate(nodes_raw)
    ]
    node_names = [str(item["name"]) for item in nodes]
    if len(node_names) != len(set(node_names)):
        raise NetworkSandboxScenarioCompileError("node names must be unique")
    nodes.sort(key=lambda item: item["name"])

    valid_endpoints = _endpoint_inventory(nodes)
    links_raw = _array(request.get("links"), "links")
    links = [
        _compile_link(
            _object(item, f"links[{index}]"),
            valid_endpoints=valid_endpoints,
            index=index,
        )
        for index, item in enumerate(links_raw)
    ]
    link_names = [str(item["name"]) for item in links]
    if len(link_names) != len(set(link_names)):
        raise NetworkSandboxScenarioCompileError("link names must be unique")

    attached: set[str] = set()
    for link in links:
        endpoints = link["endpoints"]
        assert isinstance(endpoints, list)
        for endpoint in endpoints:
            if endpoint in attached:
                raise NetworkSandboxScenarioCompileError(
                    f"interface is linked more than once: {endpoint}"
                )
            attached.add(endpoint)
    links.sort(key=lambda item: item["name"])

    node_kinds = {str(item["name"]): str(item["kind"]) for item in nodes}
    tests_raw = _array(request.get("tests"), "tests")
    if not tests_raw:
        raise NetworkSandboxScenarioCompileError("tests must not be empty")
    tests = [
        _compile_test(
            _object(item, f"tests[{index}]"),
            node_kinds=node_kinds,
            index=index,
        )
        for index, item in enumerate(tests_raw)
    ]
    test_names = [str(item["name"]) for item in tests]
    if len(test_names) != len(set(test_names)):
        raise NetworkSandboxScenarioCompileError("test names must be unique")

    scenario: dict[str, Any] = {
        "schema_version": NETWORK_SANDBOX_SCENARIO_SCHEMA_VERSION,
        "topology": {
            "nodes": nodes,
            "links": links,
        },
        "tests": tests,
    }
    if "warmup_ms" in request:
        warmup = _finite_nonnegative(request["warmup_ms"], "warmup_ms")
        if warmup:
            scenario["warmup_ms"] = warmup

    request_digest = _canonical_sha256(request)
    scenario_digest = _canonical_sha256(scenario)
    payload: dict[str, Any] = {
        "schema_version": COMPILED_SCHEMA,
        "scenario_id": scenario_id,
        "source_repository": "caotiensinh/router-configuration",
        "network_sandbox_repository": NETWORK_SANDBOX_REPOSITORY,
        "network_sandbox_sha": sandbox_sha,
        "network_sandbox_scenario_schema_version": NETWORK_SANDBOX_SCENARIO_SCHEMA_VERSION,
        "request_sha256": request_digest,
        "scenario_sha256": scenario_digest,
        "scenario": scenario,
        "evidence_class_ceiling": EvidenceClass.VIRTUAL_VERIFIED.name,
        "hardware_present": False,
        "hardware_verified": False,
        "physical_device_verified": False,
        "production_write_authorized": False,
        "production_writer_available": False,
    }
    payload["compiled_record_sha256"] = _canonical_sha256(payload)
    validate_compiled_network_sandbox_scenario(payload)
    return CompiledNetworkSandboxScenario(payload)


def validate_compiled_network_sandbox_scenario(
    record: Mapping[str, Any],
) -> None:
    if record.get("schema_version") != COMPILED_SCHEMA:
        raise NetworkSandboxScenarioCompileError("unsupported compiled scenario schema")
    if record.get("source_repository") != "caotiensinh/router-configuration":
        raise NetworkSandboxScenarioCompileError("compiled scenario source repository changed")
    if record.get("network_sandbox_repository") != NETWORK_SANDBOX_REPOSITORY:
        raise NetworkSandboxScenarioCompileError("network sandbox repository changed")
    _sha40(record.get("network_sandbox_sha"), "network_sandbox_sha")
    if (
        record.get("network_sandbox_scenario_schema_version")
        != NETWORK_SANDBOX_SCENARIO_SCHEMA_VERSION
    ):
        raise NetworkSandboxScenarioCompileError(
            "network sandbox scenario schema version changed"
        )
    _single_line(record.get("scenario_id"), "scenario_id")

    for digest_field in ("request_sha256", "scenario_sha256", "compiled_record_sha256"):
        value = str(record.get(digest_field) or "").strip().lower()
        if len(value) != 64 or any(character not in "0123456789abcdef" for character in value):
            raise NetworkSandboxScenarioCompileError(
                f"{digest_field} must be a SHA-256 digest"
            )

    if record.get("evidence_class_ceiling") != EvidenceClass.VIRTUAL_VERIFIED.name:
        raise NetworkSandboxScenarioCompileError(
            "compiler v1 evidence ceiling must remain VIRTUAL_VERIFIED"
        )
    for field in (
        "hardware_present",
        "hardware_verified",
        "physical_device_verified",
        "production_write_authorized",
        "production_writer_available",
    ):
        if record.get(field) is not False:
            raise NetworkSandboxScenarioCompileError(
                f"compiled scenario must keep {field}=false"
            )

    scenario = record.get("scenario")
    if not isinstance(scenario, Mapping):
        raise NetworkSandboxScenarioCompileError("scenario must be an object")
    if scenario.get("schema_version") != NETWORK_SANDBOX_SCENARIO_SCHEMA_VERSION:
        raise NetworkSandboxScenarioCompileError("scenario schema version changed")
    if set(scenario) - {"schema_version", "topology", "tests", "warmup_ms"}:
        raise NetworkSandboxScenarioCompileError(
            "compiled scenario contains fields outside compiler v1"
        )
    topology = scenario.get("topology")
    if not isinstance(topology, Mapping):
        raise NetworkSandboxScenarioCompileError("scenario.topology must be an object")
    if set(topology) != {"nodes", "links"}:
        raise NetworkSandboxScenarioCompileError(
            "scenario.topology must contain only nodes and links"
        )

    scenario_digest = _canonical_sha256(scenario)
    if not hmac.compare_digest(str(record["scenario_sha256"]), scenario_digest):
        raise NetworkSandboxScenarioCompileError("scenario SHA-256 mismatch")

    unsigned = dict(record)
    unsigned.pop("compiled_record_sha256", None)
    compiled_digest = _canonical_sha256(unsigned)
    if not hmac.compare_digest(
        str(record["compiled_record_sha256"]), compiled_digest
    ):
        raise NetworkSandboxScenarioCompileError("compiled record SHA-256 mismatch")
