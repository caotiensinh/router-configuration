import json
import unittest
from pathlib import Path

class ControllerAdminRbacTests(unittest.TestCase):
    def test_rbac_hierarchy_scope_and_negative_permissions_are_explicit(self):
        d=json.loads((Path(__file__).parents[1]/"artifacts"/"OMADA_CONTROLLER_ADMIN_RBAC_SCHEMA.json").read_text())
        self.assertEqual(d["task"],"7.10")
        self.assertTrue(d["controller_facts"]["master_cannot_be_deleted"])
        self.assertTrue(d["controller_facts"]["device_permissions_separate_adopt_from_manage"])
        self.assertTrue(d["controller_facts"]["local_and_cloud_principals_are_distinct"])
        self.assertTrue(d["safety"]["negative_permission_tests_required"])
        self.assertEqual(d["safety"]["unknown_permission_effect"],"DENY_UNVERIFIED")

if __name__=="__main__": unittest.main()
