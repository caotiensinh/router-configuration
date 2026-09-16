import json
from pathlib import Path


def test_security_baseline_is_advisory_driven_and_fail_closed() -> None:
    data = json.loads((Path(__file__).parents[1] / "artifacts" / "OMADA_SECURITY_BASELINE_SCHEMA.json").read_text())
    assert data["task"] == "10.1"
    assert data["authorization"]["unknown_advisory_match"] == "UNKNOWN_APPLICABILITY"
    assert data["authorization"]["latest_string_is_not_remediation_proof"] is True
    assert data["authorization"]["write_acceptance"] == "EXECUTED_UNVERIFIED"
    ids = {item["id"] for item in data["current_index_examples"]}
    assert {5287, 5256, 5216, 4917}.issubset(ids)
    assert "REMEDIATED_VERIFIED" in data["advisory_state"]
