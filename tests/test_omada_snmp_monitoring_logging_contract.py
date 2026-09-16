from __future__ import annotations

import json
from pathlib import Path


def _contract() -> dict:
    return json.loads((Path(__file__).resolve().parents[1] / "artifacts" / "OMADA_SNMP_MONITORING_LOGGING_SCHEMA.json").read_text(encoding="utf-8"))


def test_snmp_is_fail_closed_and_read_only_for_controller_managed_devices() -> None:
    data = _contract()
    assert data["task"] == "4.18"
    assert data["applicability_gate"]["rule"] == "FAIL_CLOSED"
    assert data["snmp"]["versions"] == ["v1", "v2c", "v3"]
    assert data["snmp"]["managed_device_access"] == "READ_ONLY"
    assert data["snmp"]["secret_policy"] == "NEVER_LOG_OR_EXPORT_PLAINTEXT_SECRET"


def test_monitoring_requires_operational_verification() -> None:
    data = _contract()
    assert data["verification"]["configuration_state"] == "EXECUTED_UNVERIFIED"
    checks = set(data["verification"]["pass_requires"])
    assert "successful read-only SNMP poll from the intended NMS" in checks
    assert "controller/management reachability remains healthy" in checks
