import json
import unittest
from pathlib import Path

class LoggingMonitoringBaselineTests(unittest.TestCase):
    def test_baseline_reuses_observability_and_requires_receipt_evidence(self):
        data=json.loads((Path(__file__).parent/"OMADA_LOGGING_MONITORING_BASELINE_SCHEMA.json").read_text())
        self.assertEqual(data["task"],"10.8")
        self.assertEqual(data["reuse"]["controller_observability_task"],"7.11")
        self.assertEqual(data["reuse"]["device_observability_task"],"4.18")
        self.assertTrue(data["baseline_policy"]["alert_and_event_semantics_must_remain_distinct"])
        self.assertTrue(data["baseline_policy"]["remote_log_delivery_must_be_independently_verified_when_enabled"])
        self.assertTrue(data["baseline_policy"]["secrets_and_sensitive_payloads_must_not_be_persisted"])
        self.assertEqual(data["fail_closed"]["delivery_configured_without_receipt_evidence"],"EXECUTED_UNVERIFIED")

if __name__=="__main__": unittest.main()
