import hashlib
import json
import unittest

from router_configuration.final_state_validation import FinalStateValidationError, build_final_state_validation


def sha(value):
    return hashlib.sha256(json.dumps(value,sort_keys=True,separators=(",",":"),ensure_ascii=False,default=str).encode()).hexdigest()


def lifecycle(phase="verified"):
    p={
        "schema_version":"routeros-transaction-lifecycle/1",
        "transaction_id":"1"*64,
        "envelope_sha256":"2"*64,
        "pre_state_sha256":"3"*64,
        "phase":phase,
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
        "evidence_ref":"final/readback/1",
        "transaction_id":"1"*64,
        "fresh_read":True,
        "independently_acquired":True,
        "apply_observation_reused":False,
        "management_ok":True,
        "connectivity_ok":True,
        "intended_behavior_ok":True,
        "negative_controls_ok":True,
    }
    p.update(kw)
    return p


class FinalStateValidationTests(unittest.TestCase):
    def test_exact_verified_final_state_passes_without_writer(self):
        state={"network":{"vlan":20}}
        r=build_final_state_validation(lifecycle=lifecycle(),desired_managed_state=state,final_readback_managed_state=state,evidence=evidence()).as_dict()
        self.assertEqual(r["acceptance"],"PASS")
        self.assertTrue(r["desired_matches_actual"])
        self.assertFalse(r["apply_available"])
        self.assertFalse(r["write_authorized"])

    def test_final_drift_fails_acceptance(self):
        r=build_final_state_validation(lifecycle=lifecycle(),desired_managed_state={"x":1},final_readback_managed_state={"x":2},evidence=evidence()).as_dict()
        self.assertEqual(r["acceptance"],"FAIL")
        self.assertEqual(r["drift_count"],1)

    def test_rolled_back_or_incomplete_operational_evidence_is_not_success(self):
        with self.assertRaisesRegex(FinalStateValidationError,"recovery"):
            build_final_state_validation(lifecycle=lifecycle("rolled_back"),desired_managed_state={"x":1},final_readback_managed_state={"x":1},evidence=evidence())
        with self.assertRaisesRegex(FinalStateValidationError,"negative_controls_ok"):
            build_final_state_validation(lifecycle=lifecycle(),desired_managed_state={"x":1},final_readback_managed_state={"x":1},evidence=evidence(negative_controls_ok=False))

if __name__=="__main__": unittest.main()
