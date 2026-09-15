from __future__ import annotations

import json
from pathlib import Path


def _contract() -> dict:
    path = Path(__file__).resolve().parents[1] / "artifacts" / "OMADA_CONTROLLER_ADOPTION_PROVISIONING_SCHEMA.json"
    return json.loads(path.read_text(encoding="utf-8"))


def test_adoption_has_deterministic_success_path() -> None:
    data = _contract()
    assert data["task"] == "7.03"
    assert data["state_machine"]["normal_adoption_path"] == [
        "Pending", "Adopting", "Provisioning", "Configuring", "Connected"
    ]
    assert data["state_machine"]["pass_terminal_state"] == "Connected"


def test_cross_subnet_discovery_is_fail_closed() -> None:
    data = _contract()
    remote = data["discovery"]["different_lan_subnet_vlan"]
    assert remote["direct"] is False
    assert set(remote["supported_methods"]) == {
        "Controller Inform URL", "Discovery Utility", "DHCP Option 138"
    }
    assert "communication" in remote["precondition"].lower()
    assert data["verification"]["accepted_or_in_progress_is_not_pass"] is True
