from __future__ import annotations

import json
from pathlib import Path


def _contract() -> dict:
    return json.loads((Path(__file__).resolve().parents[1] / "artifacts" / "OMADA_CONTROLLER_VERSION_COMPATIBILITY_SCHEMA.json").read_text(encoding="utf-8"))


def test_compatibility_uses_full_tuple_and_fails_closed() -> None:
    data = _contract()
    assert data["task"] == "7.04"
    key = set(data["compatibility_key"])
    assert {"controller_platform", "controller_exact_version_build", "device_model", "device_firmware", "required_feature"} <= key
    assert any("NOT_SUPPORTED_UNVERIFIED" in rule for rule in data["rules"])


def test_feature_gate_is_separate_from_controller_version() -> None:
    data = _contract()
    examples = set(data["v6_1_evidence"]["examples_requiring_device_firmware_upgrade"])
    assert {"VRF", "global LLDP", "DHCP Snooping"} <= examples
    assert "backup controller data" in data["upgrade_gate"]["preconditions"]
    assert data["sources"][0]["visual_screenshot_verified"] is False
