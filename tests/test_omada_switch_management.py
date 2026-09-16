import json
import unittest
from pathlib import Path

class SwitchManagementTests(unittest.TestCase):
    def test_switch_management_is_scoped_and_fail_closed(self):
        d=json.loads((Path(__file__).parents[1]/"artifacts"/"OMADA_SWITCH_MANAGEMENT_SCHEMA.json").read_text())
        self.assertEqual(d["task"],"7.08")
        self.assertTrue(d["controller_facts"]["single_and_batch_configuration_supported"])
        self.assertTrue(d["controller_facts"]["batch_unaltered_settings_keep_current_values"])
        self.assertTrue(d["dangerous_operations"]["wrong_management_vlan_can_break_controller_management"])
        self.assertTrue(d["dangerous_operations"]["forget_wipes_controller_related_configuration_and_history"])
        self.assertEqual(d["safety"]["unknown_support"],"NOT_SUPPORTED_UNVERIFIED")

if __name__=="__main__": unittest.main()
