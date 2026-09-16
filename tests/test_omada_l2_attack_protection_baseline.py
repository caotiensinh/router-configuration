import json
import unittest
from pathlib import Path

class L2AttackProtectionBaselineTests(unittest.TestCase):
    def test_l2_protection_dependencies_are_explicit_and_fail_closed(self):
        d=json.loads((Path(__file__).parents[1]/"artifacts"/"OMADA_L2_ATTACK_PROTECTION_BASELINE_SCHEMA.json").read_text())
        self.assertEqual(d["task"],"10.5")
        self.assertTrue(d["dependency_rules"]["arp_inspection_depends_on_valid_binding_state_where_applicable"])
        self.assertTrue(d["dependency_rules"]["ip_source_guard_depends_on_binding_state_where_applicable"])
        self.assertTrue(d["dependency_rules"]["static_ip_hosts_require_explicit_binding_strategy"])
        self.assertTrue(d["safety"]["blind_trust_or_untrust_assignment_forbidden"])
        self.assertEqual(d["safety"]["unknown_support"],"NOT_SUPPORTED_UNVERIFIED")

if __name__=="__main__": unittest.main()
