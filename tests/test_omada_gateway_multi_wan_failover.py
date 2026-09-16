import json
import unittest
from pathlib import Path

class GatewayMultiWanFailoverTests(unittest.TestCase):
    def test_multiwan_contract_is_health_bound_and_fail_closed(self):
        data=json.loads((Path(__file__).parents[1]/"artifacts"/"OMADA_GATEWAY_MULTI_WAN_FAILOVER_SCHEMA.json").read_text())
        self.assertEqual(data["task"],"5.06")
        self.assertIn("online_detection", data["state_planes"])
        self.assertTrue(data["online_detection"]["required_for_automatic_link_health_decision"])
        self.assertTrue(data["online_detection"]["link_up_does_not_prove_internet_healthy"])
        self.assertTrue(data["link_backup"]["new_session_failover_must_not_be_claimed_as_existing_session_continuity"])
        self.assertEqual(data["safety"]["unknown_capability"],"NOT_SUPPORTED_UNVERIFIED")
        self.assertEqual(data["safety"]["write_acceptance"],"EXECUTED_UNVERIFIED")

if __name__=="__main__": unittest.main()
