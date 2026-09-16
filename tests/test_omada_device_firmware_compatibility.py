import json
from pathlib import Path


def test_firmware_contract_uses_exact_tuple_and_no_global_example_default() -> None:
    data = json.loads((Path(__file__).parents[1] / "artifacts" / "OMADA_DEVICE_FIRMWARE_COMPATIBILITY_SCHEMA.json").read_text())
    assert data["task"] == "7.05"
    for field in ("device_model", "hardware_revision", "region", "current_firmware", "target_firmware", "controller_version_build"):
        assert field in data["compatibility_tuple"]
    assert data["example_constraints"]["scope_is_example_only"] is True
    assert data["example_constraints"]["upgrade_irreversible"] is True
    assert data["authorization"]["unknown_tuple"] == "NOT_SUPPORTED_UNVERIFIED"
    assert data["authorization"]["cross_region_firmware_is_not_authorized"] is True
