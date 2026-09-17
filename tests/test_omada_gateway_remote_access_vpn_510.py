import json
import unittest
from pathlib import Path


SCHEMA = Path(__file__).resolve().parents[1] / "artifacts" / "OMADA_GATEWAY_REMOTE_ACCESS_VPN_SCHEMA.json"


class OmadaGatewayRemoteAccessVpn510Tests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.data = json.loads(SCHEMA.read_text(encoding="utf-8"))

    def test_remote_access_contract_is_applicability_scoped_and_fail_closed(self):
        self.assertEqual(self.data["task"], "5.10")
        required = set(self.data["required_applicability"])
        self.assertTrue({"exact_model", "firmware_version", "region", "controller_version", "management_mode", "protocol_family"} <= required)
        self.assertTrue(self.data["invariants"]["unknown_applicability_fails_closed"])
        self.assertTrue(self.data["invariants"]["remote_access_is_distinct_from_site_to_site"])

    def test_tunnel_connected_is_not_verification(self):
        verification = self.data["verification"]
        self.assertFalse(verification["session_connected_is_sufficient"])
        self.assertTrue(verification["fresh_read_back_required"])
        self.assertTrue(verification["positive_remote_to_lan_flow_required"])
        self.assertTrue(verification["negative_unauthorized_flow_required"])
        self.assertTrue(verification["management_path_preservation_required"])

    def test_secret_material_and_hardware_overclaim_are_forbidden(self):
        security = self.data["security"]
        for key in (
            "plaintext_password_forbidden",
            "psk_forbidden_in_evidence",
            "private_key_forbidden_in_evidence",
            "certificate_private_material_forbidden",
            "token_forbidden",
            "exported_secret_config_forbidden",
        ):
            self.assertTrue(security[key])
        self.assertTrue(self.data["invariants"]["no_hardware_equivalence_claim"])
        self.assertFalse(self.data["invariants"]["production_write_authority"])


if __name__ == "__main__":
    unittest.main()
