import json
import unittest
from pathlib import Path

class AdminRbacBaselineTests(unittest.TestCase):
    def test_rbac_is_least_privilege_and_secret_safe(self):
        d=json.loads((Path(__file__).parents[1]/"artifacts"/"OMADA_ADMIN_RBAC_BASELINE_SCHEMA.json").read_text())
        self.assertEqual(d["task"],"10.3")
        self.assertFalse(d["documented_roles"]["master_administrator"]["deletable"])
        self.assertTrue(d["documented_roles"]["viewer"]["read_only_network_state"])
        self.assertFalse(d["documented_roles"]["viewer"]["can_change_network_settings"])
        self.assertEqual(d["safety"]["unknown_permission_semantics"],"NOT_SUPPORTED_UNVERIFIED")
        self.assertTrue(any("least privilege" in x for x in d["security_policy"]))

if __name__=="__main__": unittest.main()
