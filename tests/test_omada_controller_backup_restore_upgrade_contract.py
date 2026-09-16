import json
from pathlib import Path


def test_backup_restore_upgrade_contract_is_fail_closed() -> None:
    data = json.loads((Path(__file__).parents[1] / "artifacts" / "OMADA_CONTROLLER_BACKUP_RESTORE_UPGRADE_SCHEMA.json").read_text())
    assert data["task"] == "4.19"
    assert data["authorization"]["unknown_applicability"] == "NOT_SUPPORTED_UNVERIFIED"
    assert data["authorization"]["write_acceptance"] == "EXECUTED_UNVERIFIED"
    assert data["device_upgrade"]["official_firmware_only"] is True
    assert data["device_upgrade"]["do_not_assume_downgrade"] is True
    assert data["restore"]["cross_version_restore_is_not_assumed"] is True
    assert "controller_version_build" in data["applicability_key"]
    assert "region" in data["applicability_key"]
