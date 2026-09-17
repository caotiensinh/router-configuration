import json
import unittest
from pathlib import Path


class OmadaGatewaySiteToSiteVpn509Tests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.data = json.loads(
            (Path(__file__).parents[1] / "artifacts" / "OMADA_GATEWAY_SITE_TO_SITE_VPN_SCHEMA.json").read_text()
        )

    def test_site_to_site_contract_is_fail_closed_and_scoped(self):
        d = self.data
        self.assertEqual(d["task"], "5.09")
        self.assertTrue(d["workflow_types"]["auto_ipsec"]["same_controller_sites_required"])
        self.assertTrue(d["workflow_types"]["manual_ipsec"]["explicit_remote_peer_required"])
        self.assertEqual(d["applicability"]["unknown_support"], "NOT_SUPPORTED_UNVERIFIED")
        self.assertTrue(d["dependencies"]["non_overlapping_local_remote_subnets_required"])

    def test_secrets_never_enter_evidence(self):
        boundary = self.data["secret_boundary"]
        for key in ("psk_in_evidence", "private_key_in_evidence", "password_in_evidence", "token_in_evidence"):
            self.assertFalse(boundary[key])
        self.assertTrue(boundary["secret_values_are_references_only"])

    def test_configuration_acceptance_is_not_verification(self):
        verification = self.data["verification"]
        self.assertFalse(verification["configuration_acceptance_alone_is_pass"])
        self.assertTrue(verification["fresh_readback_required"])
        self.assertTrue(verification["operational_tunnel_state_required"])
        self.assertTrue(verification["negative_non_allowed_flow_check_required"])
        self.assertTrue(verification["management_path_health_required"])
        self.assertFalse(self.data["hardware_boundary"]["virtual_or_document_evidence_can_claim_hardware_verified"])


if __name__ == "__main__":
    unittest.main()
