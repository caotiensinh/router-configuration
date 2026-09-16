import json
from pathlib import Path


def test_diagnostics_contract_is_evidence_first_and_fail_closed() -> None:
    data = json.loads((Path(__file__).parents[1] / "artifacts" / "OMADA_SWITCH_DIAGNOSTICS_TROUBLESHOOTING_SCHEMA.json").read_text())
    assert data["task"] == "4.20"
    assert data["safety"]["read_only_evidence_precedes_mutation"] is True
    assert data["safety"]["factory_reset_is_not_a_first_line_diagnostic"] is True
    assert data["safety"]["firmware_upgrade_is_not_a_first_line_diagnostic"] is True
    assert data["safety"]["global_acl_or_security_disable_is_forbidden_as_a_generic_fix"] is True
    assert data["safety"]["unknown_tool_support"] == "NOT_SUPPORTED_UNVERIFIED"
    assert data["diagnostic_planes"]["physical_link"]["mutation_required"] is False
    assert "ROOT_CAUSE_UNRESOLVED" in data["outcomes"]
