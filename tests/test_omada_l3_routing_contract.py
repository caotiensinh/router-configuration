from __future__ import annotations

import json
from pathlib import Path


def _contract() -> dict:
    path = Path(__file__).resolve().parents[1] / "artifacts" / "OMADA_JETSTREAM_L3_ROUTING_SCHEMA.json"
    return json.loads(path.read_text(encoding="utf-8"))


def test_l3_routing_contract_is_fail_closed() -> None:
    data = _contract()
    assert data["task"] == "4.17"
    assert data["applicability_gate"]["rule"] == "FAIL_CLOSED"
    required = set(data["applicability_gate"]["required"])
    assert {"device_model", "hardware_revision", "firmware_version", "controller_version"} <= required


def test_static_route_verification_is_operational_not_acceptance_only() -> None:
    data = _contract()
    route = data["state_planes"]["static_route"]
    assert route["distance"] == {"min": 1, "max": 255, "unreachable": 255}
    checks = set(data["verification"]["pass_requires"])
    assert "expected route present in routing table" in checks
    assert "next-hop reachability" in checks
    assert "controller/management reachability remains healthy" in checks
    assert data["verification"]["configuration_state"] == "EXECUTED_UNVERIFIED"
