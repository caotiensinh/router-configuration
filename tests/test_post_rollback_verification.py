import hashlib
import json
import unittest

from router_configuration.post_rollback_verification import PostRollbackVerificationError, build_post_rollback_verification


def sha(value):
    return hashlib.sha256(json.dumps(value,sort_keys=True,separators=(",",":"),ensure_ascii=False,default=str).encode()).hexdigest()

def lifecycle():
    p={
        "schema_version":"routeros-transaction-lifecycle/1",
        "transaction_id":"1"*64,
        "envelope_sha256":"2"*64,
        "pre_state_sha256":"3"*64,
        "phase":"rollback_observed",
        "sequence":5,
        "events":[],
        "claim":"audit_state_only",
        "secret_values_present":False,
        "transport_present":False,
        "apply_available":False,
        "rollback_available":False,
        "production_writer_available":False,
        "write_authorized":False,
    }
    p["lifecycle_sha256"]=sha(p)
    return p

def evidence(**kw):
    p={
        "evidence_ref":"rollback/readback/1",
        "transaction_id":"1"*64,
        "pre_state_sha256":"3"*64,
        "fresh_read":True,
        "independently_acquired":True,
        "apply_observation_reused":False,
        "management_recovered":True,
        "connectivity_recovered":True,
    }
    p.update(kw); return p

class PostRollbackVerificationTests(unittest.TestCase):
    def test_exact_fresh_recovery_emits_rolled_back_eligible_evidence(self):
        state={"network":{"vlan":20}}
        r=build_post_rollback_verification(lifecycle=lifecycle(),pre_state_managed_state=state,rollback_readback_managed_state=state,evidence=evidence()).as_dict()
        self.assertEqual(r["acceptance"],"PASS")
        self.assertTrue(r["managed_objects_reconciled"])
        self.assertEqual(r["lifecycle_transition_evidence"]["rollback_state_sha256"],"3"*64)
        self.assertFalse(r["rollback_available"])
        self.assertFalse(r["write_authorized"])

    def test_drift_is_fail_not_recovery_success(self):
        r=build_post_rollback_verification(lifecycle=lifecycle(),pre_state_managed_state={"x":1},rollback_readback_managed_state={"x":2},evidence=evidence()).as_dict()
        self.assertEqual(r["acceptance"],"FAIL")
        self.assertFalse(r["managed_objects_reconciled"])
        self.assertEqual(r["drift_count"],1)

    def test_wrong_phase_stale_or_unhealthy_recovery_fails_closed(self):
        bad=lifecycle(); bad["phase"]="rollback_required"; bad.pop("lifecycle_sha256"); bad["lifecycle_sha256"]=sha(bad)
        with self.assertRaisesRegex(PostRollbackVerificationError,"rollback_observed"):
            build_post_rollback_verification(lifecycle=bad,pre_state_managed_state={"x":1},rollback_readback_managed_state={"x":1},evidence=evidence())
        with self.assertRaisesRegex(PostRollbackVerificationError,"fresh_read=true"):
            build_post_rollback_verification(lifecycle=lifecycle(),pre_state_managed_state={"x":1},rollback_readback_managed_state={"x":1},evidence=evidence(fresh_read=False))
        with self.assertRaisesRegex(PostRollbackVerificationError,"management_recovered"):
            build_post_rollback_verification(lifecycle=lifecycle(),pre_state_managed_state={"x":1},rollback_readback_managed_state={"x":1},evidence=evidence(management_recovered=False))

if __name__=="__main__": unittest.main()
