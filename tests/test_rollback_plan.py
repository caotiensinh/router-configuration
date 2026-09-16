import hashlib
import json
import unittest

from router_configuration.m02_state_engine import StateEngine
from router_configuration.ordered_execution import build_ordered_execution_plan
from router_configuration.rollback_plan import RollbackPlanError, build_rollback_plan
from router_configuration.stop_on_failure import evaluate_execution_checkpoint


def sha(value):
    return hashlib.sha256(json.dumps(value,sort_keys=True,separators=(",",":"),default=str).encode()).hexdigest()


def lifecycle(plan_id):
    payload={
        "schema_version":"routeros-transaction-lifecycle/1",
        "transaction_id":"1"*64,
        "envelope_sha256":"2"*64,
        "pre_state_sha256":"3"*64,
        "phase":"rollback_required",
        "sequence":1,
        "events":[],
        "claim":"audit_state_only",
        "secret_values_present":False,
        "transport_present":False,
        "apply_available":False,
        "rollback_available":False,
        "production_writer_available":False,
        "write_authorized":False,
    }
    payload["lifecycle_sha256"]=sha(payload)
    return payload


class RollbackPlanTests(unittest.TestCase):
    def setUp(self):
        self.change=StateEngine().build_plan({"a":1,"b":2},{"a":0,"b":0})
        self.ordered=build_ordered_execution_plan(self.change)
        first=self.ordered.steps[0].operation_id
        self.stop=evaluate_execution_checkpoint(
            plan=self.ordered,
            completed_operation_ids=[],
            observation={"operation_id":first,"apply_ok":False,"verification_ok":False,"evidence_ref":"failure/1"},
        ).as_dict()

    def test_confirmed_prefix_rolls_back_in_reverse_order(self):
        ids=[s.operation_id for s in self.ordered.steps]
        result=build_rollback_plan(
            change_plan=self.change,ordered_plan=self.ordered,stop_decision=self.stop,
            lifecycle=lifecycle(self.change.plan_id),backup_ref="backup/pre",affected_operation_ids=ids,
            mutation_scope_confirmed=True,
        ).as_dict()
        self.assertEqual(result["strategy"],"INVERSE_CONFIRMED_PREFIX")
        self.assertEqual([s["source_operation_id"] for s in result["steps"]],list(reversed(ids)))
        self.assertFalse(result["rollback_available"])
        self.assertTrue(result["requires_fresh_post_rollback_verification"])

    def test_uncertain_scope_falls_back_to_bound_backup(self):
        result=build_rollback_plan(
            change_plan=self.change,ordered_plan=self.ordered,stop_decision=self.stop,
            lifecycle=lifecycle(self.change.plan_id),backup_ref="backup/pre",affected_operation_ids=None,
            mutation_scope_confirmed=False,
        ).as_dict()
        self.assertEqual(result["strategy"],"RESTORE_BOUND_PRE_STATE_BACKUP")
        self.assertEqual(result["steps"],[])
        self.assertEqual(result["pre_state_sha256"],"3"*64)

    def test_non_halt_wrong_phase_and_nonprefix_fail_closed(self):
        bad_stop=dict(self.stop); bad_stop["decision"]="ADVANCE"; bad_stop.pop("decision_sha256"); bad_stop["decision_sha256"]=sha(bad_stop)
        with self.assertRaisesRegex(RollbackPlanError,"HALT"):
            build_rollback_plan(change_plan=self.change,ordered_plan=self.ordered,stop_decision=bad_stop,lifecycle=lifecycle(self.change.plan_id),backup_ref="b",affected_operation_ids=[],mutation_scope_confirmed=True)
        bad_life=lifecycle(self.change.plan_id); bad_life["phase"]="verification_pending"; bad_life.pop("lifecycle_sha256"); bad_life["lifecycle_sha256"]=sha(bad_life)
        with self.assertRaisesRegex(RollbackPlanError,"rollback_required"):
            build_rollback_plan(change_plan=self.change,ordered_plan=self.ordered,stop_decision=self.stop,lifecycle=bad_life,backup_ref="b",affected_operation_ids=[],mutation_scope_confirmed=True)
        ids=[s.operation_id for s in self.ordered.steps]
        with self.assertRaisesRegex(RollbackPlanError,"exact ordered prefix"):
            build_rollback_plan(change_plan=self.change,ordered_plan=self.ordered,stop_decision=self.stop,lifecycle=lifecycle(self.change.plan_id),backup_ref="b",affected_operation_ids=[ids[-1]],mutation_scope_confirmed=True)

if __name__=="__main__": unittest.main()
