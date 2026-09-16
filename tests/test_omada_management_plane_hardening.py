import json
import unittest
from pathlib import Path


class OmadaManagementPlaneHardeningTests(unittest.TestCase):
    def test_management_hardening_separates_vendor_facts_from_security_policy(self) -> None:
        data = json.loads((Path(__file__).parents[1] / "artifacts" / "OMADA_MANAGEMENT_PLANE_HARDENING_SCHEMA.json").read_text())
        self.assertEqual(data["task"], "10.2")
        self.assertIs(data["vendor_facts"]["controller_management_and_portal_ports_should_be_separate"], True)
        self.assertIs(data["vendor_facts"]["management_vlan_requires_topology_correctness"], True)
        self.assertEqual(data["authorization"]["unknown_support"], "NOT_SUPPORTED_UNVERIFIED")
        self.assertIs(data["authorization"]["management_path_change_is_critical"], True)
        policy = " ".join(data["security_policy_layer"]).lower()
        self.assertIn("encrypted management protocols", policy)
        self.assertIn("private keys", policy)
        self.assertIs(data["rollback"]["never_assume_oob_access_exists"], True)


if __name__ == "__main__":
    unittest.main()
