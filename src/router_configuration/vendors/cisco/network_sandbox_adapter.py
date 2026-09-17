"""Simulation-only adapter for Network_Sandbox_Runtime snapshots.

This module intentionally does not feed simulated data into the live IOS XE
YANG normalizers. It validates the subset of router/switch behavior that the
Network Sandbox snapshot contract can reproduce while keeping C05/C06/C10
live acceptance false.
"""

from __future__ import annotations

import hashlib
from ipaddress import ip_interface, ip_network
import json
from typing import Mapping, Sequence

from .simulation_evidence import build_simulation_evidence


NETWORK_SANDBOX_REPOSITORY = "caotiensinh/Network_Sandbox_Runtime"
SNAPSHOT_CONTRACT = "NetworkRuntime.snapshot/v1"
C05_LOGIC_STATUS = "PARTIAL_SIMULATION_PASS"
C06_LOGIC_STATUS = "PARTIAL_SIMULATION_PASS"
C10_LOGIC_STATUS = "SIMULATION_PASS"

_SENSITIVE_PARTS = (
    "password", "secret", "private-key", "private_key", "pre-shared-key",
    "preshared-key", "psk", "token", "community", "key-string", "key_string",
)

_ROUTER_GAPS = (
    "live IOS XE YANG inventory",
    "live IOS XE interface admin/oper state",
    "live IOS XE IPv6 operational state",
)
_SWITCH_GAPS = (
    "live IOS XE YANG inventory",
    "live IOS XE VLAN operational status",
    "live IOS XE MAC table",
    "live IOS XE STP operational state",
)


class CiscoNetworkSandboxAdapterError(ValueError):
    """Raised when sandbox evidence violates the simulation-only contract."""


def canonical_sha256(value: object) -> str:
    encoded = json.dumps(
        value, sort_keys=True, separators=(",", ":"), ensure_ascii=True
    ).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def _reject_sensitive(value: object, path: str = "$") -> None:
    if isinstance(value, Mapping):
        for key, child in value.items():
            normalized = str(key).lower().replace("_", "-")
            if any(part.replace("_", "-") in normalized for part in _SENSITIVE_PARTS):
                raise CiscoNetworkSandboxAdapterError(
                    f"sensitive field rejected at {path}.{key}"
                )
            _reject_sensitive(child, f"{path}.{key}")
    elif isinstance(value, Sequence) and not isinstance(value, (str, bytes, bytearray)):
        for index, child in enumerate(value):
            _reject_sensitive(child, f"{path}[{index}]")


def _snapshot(snapshot: object) -> Mapping[str, object]:
    if not isinstance(snapshot, Mapping):
        raise CiscoNetworkSandboxAdapterError("snapshot must be an object")
    _reject_sensitive(snapshot)
    nodes = snapshot.get("nodes")
    links = snapshot.get("links")
    conntrack = snapshot.get("conntrack")
    if not isinstance(nodes, Mapping):
        raise CiscoNetworkSandboxAdapterError("snapshot.nodes must be an object")
    if not isinstance(links, Mapping):
        raise CiscoNetworkSandboxAdapterError("snapshot.links must be an object")
    if not isinstance(conntrack, Sequence) or isinstance(conntrack, (str, bytes, bytearray)):
        raise CiscoNetworkSandboxAdapterError("snapshot.conntrack must be an array")
    return snapshot


def _node(snapshot: Mapping[str, object], node_name: str, expected_kind: str) -> Mapping[str, object]:
    nodes = snapshot["nodes"]
    assert isinstance(nodes, Mapping)
    raw = nodes.get(node_name)
    if not isinstance(raw, Mapping):
        raise CiscoNetworkSandboxAdapterError(f"node not found: {node_name}")
    if raw.get("kind") != expected_kind:
        raise CiscoNetworkSandboxAdapterError(
            f"node {node_name} must have kind={expected_kind}"
        )
    interfaces = raw.get("interfaces")
    routes = raw.get("routes")
    if not isinstance(interfaces, Mapping):
        raise CiscoNetworkSandboxAdapterError("node.interfaces must be an object")
    if not isinstance(routes, Sequence) or isinstance(routes, (str, bytes, bytearray)):
        raise CiscoNetworkSandboxAdapterError("node.routes must be an array")
    return raw


def _link_state_by_endpoint(snapshot: Mapping[str, object]) -> dict[str, bool]:
    links = snapshot["links"]
    assert isinstance(links, Mapping)
    result: dict[str, bool] = {}
    for link_name, raw in links.items():
        if not isinstance(raw, Mapping):
            raise CiscoNetworkSandboxAdapterError(f"link must be an object: {link_name}")
        up = raw.get("up")
        if not isinstance(up, bool):
            raise CiscoNetworkSandboxAdapterError(f"link.up must be boolean: {link_name}")
        for side in ("a", "b"):
            endpoint = raw.get(side)
            if not isinstance(endpoint, str) or ":" not in endpoint:
                raise CiscoNetworkSandboxAdapterError(
                    f"link endpoint must be node:interface: {link_name}.{side}"
                )
            if endpoint in result:
                raise CiscoNetworkSandboxAdapterError(
                    f"duplicate link endpoint: {endpoint}"
                )
            result[endpoint] = up
    return result


def _vlan_id(value: object, field: str, *, optional: bool = True) -> int | None:
    if value is None and optional:
        return None
    if isinstance(value, bool) or not isinstance(value, int) or not 1 <= value <= 4094:
        raise CiscoNetworkSandboxAdapterError(f"invalid VLAN id: {field}")
    return value


def _allowed_vlans(value: object, field: str) -> tuple[int, ...]:
    if value is None:
        return ()
    if not isinstance(value, Sequence) or isinstance(value, (str, bytes, bytearray)):
        raise CiscoNetworkSandboxAdapterError(f"{field} must be an array")
    values: list[int] = []
    for item in value:
        vlan_id = _vlan_id(item, field, optional=False)
        assert vlan_id is not None
        values.append(vlan_id)
    return tuple(sorted(set(values)))


def normalize_router_simulation_state(
    snapshot: object,
    *,
    node_name: str,
) -> dict:
    """Validate the router subset exposed by NetworkRuntime.snapshot()."""

    doc = _snapshot(snapshot)
    raw = _node(doc, node_name, "router")
    link_state = _link_state_by_endpoint(doc)

    interfaces_raw = raw["interfaces"]
    assert isinstance(interfaces_raw, Mapping)
    interfaces: list[dict] = []
    for name, item in interfaces_raw.items():
        if not isinstance(name, str) or not name.strip() or not isinstance(item, Mapping):
            raise CiscoNetworkSandboxAdapterError("router interface entry is invalid")
        address = item.get("address")
        if address is not None:
            if not isinstance(address, str):
                raise CiscoNetworkSandboxAdapterError("router interface address must be text")
            try:
                parsed = ip_interface(address)
            except ValueError as exc:
                raise CiscoNetworkSandboxAdapterError(
                    f"invalid router interface address: {name}"
                ) from exc
            if parsed.version != 4:
                raise CiscoNetworkSandboxAdapterError(
                    "Network Sandbox router adapter currently admits IPv4 only"
                )
            address = str(parsed)
        mode = item.get("mode")
        if mode != "routed":
            raise CiscoNetworkSandboxAdapterError(
                f"router interface must use routed mode: {name}"
            )
        interfaces.append({
            "name": name,
            "ipv4_cidr": address,
            "link_up": link_state.get(f"{node_name}:{name}"),
        })

    routes: list[dict] = []
    routes_raw = raw["routes"]
    assert isinstance(routes_raw, Sequence)
    for item in routes_raw:
        if not isinstance(item, Mapping):
            raise CiscoNetworkSandboxAdapterError("router route entry must be an object")
        destination = item.get("destination")
        out_interface = item.get("out_interface")
        next_hop = item.get("next_hop")
        metric = item.get("metric")
        if not isinstance(destination, str):
            raise CiscoNetworkSandboxAdapterError("route.destination must be text")
        try:
            network = ip_network(destination, strict=False)
        except ValueError as exc:
            raise CiscoNetworkSandboxAdapterError("invalid route.destination") from exc
        if network.version != 4:
            raise CiscoNetworkSandboxAdapterError(
                "Network Sandbox router adapter currently admits IPv4 routes only"
            )
        if not isinstance(out_interface, str) or out_interface not in interfaces_raw:
            raise CiscoNetworkSandboxAdapterError("route.out_interface is unknown")
        if next_hop is not None and not isinstance(next_hop, str):
            raise CiscoNetworkSandboxAdapterError("route.next_hop must be text or null")
        if isinstance(metric, bool) or not isinstance(metric, int) or metric < 0:
            raise CiscoNetworkSandboxAdapterError("route.metric must be a non-negative integer")
        routes.append({
            "destination": str(network),
            "out_interface": out_interface,
            "next_hop": next_hop,
            "metric": metric,
        })

    payload = {
        "contract": SNAPSHOT_CONTRACT,
        "source": NETWORK_SANDBOX_REPOSITORY,
        "node": node_name,
        "kind": "router",
        "interfaces": sorted(interfaces, key=lambda item: item["name"]),
        "routes": sorted(
            routes,
            key=lambda item: (
                item["destination"],
                item["out_interface"],
                "" if item["next_hop"] is None else item["next_hop"],
                item["metric"],
            ),
        ),
        "logic_status": C05_LOGIC_STATUS,
        "live_acceptance": False,
        "canonical_acceptance_promoted": False,
        "coverage_gaps": list(_ROUTER_GAPS),
    }
    return {**payload, "state_digest_sha256": canonical_sha256(payload)}


def normalize_switch_simulation_state(
    snapshot: object,
    *,
    node_name: str,
) -> dict:
    """Validate access/trunk semantics exposed by NetworkRuntime.snapshot()."""

    doc = _snapshot(snapshot)
    raw = _node(doc, node_name, "switch")
    link_state = _link_state_by_endpoint(doc)

    interfaces_raw = raw["interfaces"]
    assert isinstance(interfaces_raw, Mapping)
    interfaces: list[dict] = []
    for name, item in interfaces_raw.items():
        if not isinstance(name, str) or not name.strip() or not isinstance(item, Mapping):
            raise CiscoNetworkSandboxAdapterError("switch interface entry is invalid")
        mode = item.get("mode")
        if mode not in {"access", "trunk"}:
            raise CiscoNetworkSandboxAdapterError(
                f"switch interface must use access/trunk mode: {name}"
            )
        access_vlan = _vlan_id(item.get("access_vlan"), f"{name}.access_vlan")
        native_vlan = _vlan_id(item.get("native_vlan"), f"{name}.native_vlan")
        allowed = _allowed_vlans(item.get("allowed_vlans"), f"{name}.allowed_vlans")
        if mode == "access":
            if access_vlan is None:
                raise CiscoNetworkSandboxAdapterError(
                    f"access port requires access_vlan: {name}"
                )
            if native_vlan is not None or allowed:
                raise CiscoNetworkSandboxAdapterError(
                    f"access port cannot carry trunk fields: {name}"
                )
        else:
            if access_vlan is not None:
                raise CiscoNetworkSandboxAdapterError(
                    f"trunk port cannot carry access_vlan: {name}"
                )
        interfaces.append({
            "name": name,
            "mode": mode,
            "access_vlan": access_vlan,
            "native_vlan": native_vlan,
            "allowed_vlans": list(allowed),
            "all_vlans_allowed": mode == "trunk" and not allowed,
            "link_up": link_state.get(f"{node_name}:{name}"),
        })

    payload = {
        "contract": SNAPSHOT_CONTRACT,
        "source": NETWORK_SANDBOX_REPOSITORY,
        "node": node_name,
        "kind": "switch",
        "interfaces": sorted(interfaces, key=lambda item: item["name"]),
        "logic_status": C06_LOGIC_STATUS,
        "live_acceptance": False,
        "canonical_acceptance_promoted": False,
        "coverage_gaps": list(_SWITCH_GAPS),
    }
    return {**payload, "state_digest_sha256": canonical_sha256(payload)}


def evaluate_recovery_simulation(
    pre_snapshot: object,
    fault_snapshot: object,
    recovered_snapshot: object,
) -> dict:
    """Require a real simulated fault and byte-stable canonical restoration."""

    pre = _snapshot(pre_snapshot)
    fault = _snapshot(fault_snapshot)
    recovered = _snapshot(recovered_snapshot)
    pre_digest = canonical_sha256(pre)
    fault_digest = canonical_sha256(fault)
    recovered_digest = canonical_sha256(recovered)

    fault_observed = fault_digest != pre_digest
    restored = recovered_digest == pre_digest
    logic_pass = fault_observed and restored
    status = C10_LOGIC_STATUS if logic_pass else "SIMULATION_FAIL"
    return {
        "contract": SNAPSHOT_CONTRACT,
        "source": NETWORK_SANDBOX_REPOSITORY,
        "pre_state_digest": pre_digest,
        "fault_state_digest": fault_digest,
        "recovered_state_digest": recovered_digest,
        "fault_observed": fault_observed,
        "restored_exactly": restored,
        "logic_pass": logic_pass,
        "logic_status": status,
        "live_acceptance": False,
        "canonical_acceptance_promoted": False,
    }


def build_network_sandbox_logic_evidence(
    *,
    router_configuration_sha: str,
    network_sandbox_sha: str,
    simulation_profile: str,
    scenario: object,
    input_payload: object,
    pre_snapshot: object,
    post_snapshot: object,
    evidence_refs: Sequence[str],
    tested_logic: Sequence[str],
) -> dict:
    """Build cross-repo provenance while preserving simulation-only scope."""

    _snapshot(pre_snapshot)
    _snapshot(post_snapshot)
    return build_simulation_evidence(
        source_sha=router_configuration_sha,
        simulator_sha=network_sandbox_sha,
        simulation_profile=simulation_profile,
        scenario_digest=canonical_sha256(scenario),
        input_digest=canonical_sha256(input_payload),
        pre_state_digest=canonical_sha256(pre_snapshot),
        post_state_digest=canonical_sha256(post_snapshot),
        environment_kind="qualified_simulation",
        tested_logic=list(tested_logic),
        evidence_refs=list(evidence_refs),
    )
