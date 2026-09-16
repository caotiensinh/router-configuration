import json
from pathlib import Path


def test_management_hardening_separates_vendor_facts_from_security_policy() -> None:
    data = json.loads((Path(__file__).parents[1] / "artifacts" / "OMADA_MANAGEMENT_PLANE_HARDENING_SCHEMA.json").read_text())
    assert data["task"] == "10.2"
    assert data["vendor_facts"]["controller_management_and_portal_ports_should_be_separate"] is True
    assert data["vendor_facts"]["management_vlan_requires_topology_correctness"] is True
    assert data["authorization"]["unknown_support"] == "NOT_SUPPORTED_UNVERIFIED"
    assert data["authorization"]["management_path_change_is_critical"] is True
    policy = " ".join(data["security_policy_layer"]).lower()
    assert "encrypted management protocols" in policy
    assert "private keys" in policy
    assert data["rollback"]["never_assume_oob_access_exists"] is True
