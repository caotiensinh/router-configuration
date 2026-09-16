import json
from pathlib import Path


def test_template_contract_separates_planes_and_protects_management_path() -> None:
    data = json.loads((Path(__file__).parents[1] / "artifacts" / "OMADA_CONFIGURATION_TEMPLATES_PROFILES_SCHEMA.json").read_text())
    assert data["task"] == "7.06"
    assert set(("site_template", "device_template", "switch_port_profile", "local_override")).issubset(data["state_planes"])
    assert data["authority"]["site_template_current_documented_min_controller"] == "5.15.20"
    assert data["authority"]["hardware_controller_site_template_support"] == "NOT_SUPPORTED_UNVERIFIED"
    assert data["site_template"]["selected_configurable_modules_are_fixed_after_creation"] is True
    assert data["device_template"]["exact_device_model_binding_required"] is True
    assert data["device_template"]["auto_bind_can_disconnect_network_when_template_is_wrong"] is True
    assert data["authorization"]["pre_bind_diff_required"] is True
    assert data["authorization"]["management_path_impact_check_required"] is True
