import json
import unittest
from pathlib import Path


class OmadaConfigurationTemplatesProfilesTests(unittest.TestCase):
    def test_template_contract_separates_planes_and_protects_management_path(self) -> None:
        data = json.loads((Path(__file__).parents[1] / "artifacts" / "OMADA_CONFIGURATION_TEMPLATES_PROFILES_SCHEMA.json").read_text())
        self.assertEqual(data["task"], "7.06")
        self.assertTrue(set(("site_template", "device_template", "switch_port_profile", "local_override")).issubset(data["state_planes"]))
        self.assertEqual(data["authority"]["site_template_current_documented_min_controller"], "5.15.20")
        self.assertEqual(data["authority"]["hardware_controller_site_template_support"], "NOT_SUPPORTED_UNVERIFIED")
        self.assertIs(data["site_template"]["selected_configurable_modules_are_fixed_after_creation"], True)
        self.assertIs(data["device_template"]["exact_device_model_binding_required"], True)
        self.assertIs(data["device_template"]["auto_bind_can_disconnect_network_when_template_is_wrong"], True)
        self.assertIs(data["authorization"]["pre_bind_diff_required"], True)
        self.assertIs(data["authorization"]["management_path_impact_check_required"], True)


if __name__ == "__main__":
    unittest.main()
