import json
import unittest
from pathlib import Path

class ControllerApiIntegrationCapabilitiesTests(unittest.TestCase):
    def test_api_surfaces_are_version_bound_least_privilege_and_secret_safe(self):
        data=json.loads((Path(__file__).parents[1]/"artifacts"/"OMADA_CONTROLLER_API_INTEGRATION_CAPABILITIES_SCHEMA.json").read_text())
        self.assertEqual(data["task"],"7.13")
        self.assertTrue(data["vendor_facts"]["oauth_authorization_code_and_client_modes_are_documented"])
        self.assertTrue(data["vendor_facts"]["client_mode_can_bind_role_and_site_privilege"])
        self.assertTrue(data["vendor_facts"]["external_portal_api_is_version_banded"])
        self.assertTrue(data["integration_policy"]["exact_online_api_document_for_running_controller_is_authoritative_for_endpoint_method_and_parameters"])
        self.assertTrue(data["integration_policy"]["client_secret_access_token_refresh_token_and_webhook_secret_must_not_be_persisted"])
        self.assertTrue(data["integration_policy"]["api_success_response_does_not_replace_fresh_state_verification_for_configuration_changes"])
        self.assertEqual(data["safety"]["unknown_endpoint_or_version_support"],"NOT_SUPPORTED_UNVERIFIED")

if __name__=="__main__": unittest.main()
