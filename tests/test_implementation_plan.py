import unittest

from router_configuration.implementation_plan import ImplementationPlanError, build_implementation_plan
from router_configuration.m02_state_engine import StateEngine


class ImplementationPlanTests(unittest.TestCase):
    def test_low_risk_plan_is_deterministic_and_non_executable(self):
        change=StateEngine().build_plan({"logging":{"enabled":True}}, {"logging":{"enabled":False}})
        kw=dict(current_main_sha="56e51c0119a15226f13c9a09c9553577c8656e8e", evidence_refs=["canonical:233/340"])
        a=build_implementation_plan(change, **kw).as_dict()
        b=build_implementation_plan(change, **kw).as_dict()
        self.assertEqual(a,b)
        self.assertFalse(a["risk_controls"]["high_risk_change"])
        self.assertFalse(a["transport_present"])
        self.assertFalse(a["write_authorized"])

    def test_network_change_requires_window_backup_and_rollback(self):
        change=StateEngine().build_plan({"routing":{"default_route":"wan2"}}, {"routing":{"default_route":"wan1"}})
        base=dict(current_main_sha="56e51c0119a15226f13c9a09c9553577c8656e8e", evidence_refs=["plan:route-change"])
        with self.assertRaises(ImplementationPlanError):
            build_implementation_plan(change, **base)
        result=build_implementation_plan(change, change_window="2026-09-17T01:00+09:00", backup_ref="backup:pre", rollback_ref="rollback:bound", **base).as_dict()
        self.assertTrue(result["risk_controls"]["high_risk_change"])
        self.assertEqual(result["risk_controls"]["backup_ref"],"backup:pre")

    def test_bad_sha_or_duplicate_evidence_fails_closed(self):
        change=StateEngine().build_plan({}, {})
        with self.assertRaises(ImplementationPlanError):
            build_implementation_plan(change,current_main_sha="main",evidence_refs=["e1"])
        with self.assertRaises(ImplementationPlanError):
            build_implementation_plan(change,current_main_sha="56e51c0119a15226f13c9a09c9553577c8656e8e",evidence_refs=["e1","e1"])

if __name__=="__main__": unittest.main()
