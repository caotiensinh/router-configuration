import unittest
from router_configuration.m02_state_engine import StateEngine
from router_configuration.ordered_execution import build_ordered_execution_plan
from router_configuration.stop_on_failure import StopOnFailureError, evaluate_execution_checkpoint

class StopOnFailureTests(unittest.TestCase):
    def setUp(self):
        cp=StateEngine().build_plan({"a":1,"b":2},{"a":0,"b":0})
        self.plan=build_ordered_execution_plan(cp)

    def test_success_advances_exactly_one_step(self):
        first=self.plan.steps[0].operation_id
        result=evaluate_execution_checkpoint(plan=self.plan,completed_operation_ids=[],observation={"operation_id":first,"apply_ok":True,"verification_ok":True,"evidence_ref":"ev/1"}).as_dict()
        self.assertEqual(result["decision"],"ADVANCE")
        self.assertFalse(result["halt_forward_progress"])
        self.assertFalse(result["rollback_required"])
        self.assertEqual(result["next_operation_id"],self.plan.steps[1].operation_id)

    def test_failure_halts_and_routes_to_rollback_without_executing_it(self):
        first=self.plan.steps[0].operation_id
        result=evaluate_execution_checkpoint(plan=self.plan,completed_operation_ids=[],observation={"operation_id":first,"apply_ok":False,"verification_ok":False,"evidence_ref":"ev/fail"}).as_dict()
        self.assertEqual(result["decision"],"HALT")
        self.assertTrue(result["halt_forward_progress"])
        self.assertTrue(result["rollback_required"])
        self.assertIsNone(result["next_operation_id"])
        self.assertFalse(result["rollback_available"])
        self.assertFalse(result["write_authorized"])

    def test_out_of_order_duplicate_and_runtime_fields_fail_closed(self):
        ids=[s.operation_id for s in self.plan.steps]
        with self.assertRaisesRegex(StopOnFailureError,"exact ordered prefix"):
            evaluate_execution_checkpoint(plan=self.plan,completed_operation_ids=[ids[1]],observation={"operation_id":ids[0],"apply_ok":True,"verification_ok":True,"evidence_ref":"x"})
        with self.assertRaisesRegex(StopOnFailureError,"duplicates"):
            evaluate_execution_checkpoint(plan=self.plan,completed_operation_ids=[ids[0],ids[0]],observation={"operation_id":ids[1],"apply_ok":True,"verification_ok":True,"evidence_ref":"x"})
        with self.assertRaisesRegex(StopOnFailureError,"runtime-capability"):
            evaluate_execution_checkpoint(plan=self.plan,completed_operation_ids=[],observation={"operation_id":ids[0],"apply_ok":True,"verification_ok":True,"evidence_ref":"x","token":"no"})

if __name__=="__main__": unittest.main()
