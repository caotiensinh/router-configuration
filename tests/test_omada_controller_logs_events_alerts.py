import json
import unittest
from pathlib import Path

class ControllerLogsEventsAlertsTests(unittest.TestCase):
    def test_logs_alerts_events_are_separate_and_secret_safe(self):
        d=json.loads((Path(__file__).parents[1]/"artifacts"/"OMADA_CONTROLLER_LOGS_EVENTS_ALERTS_SCHEMA.json").read_text())
        self.assertEqual(d["task"],"7.11")
        self.assertTrue(d["controller_facts"]["alerts_events_and_audit_logs_are_distinct"])
        self.assertTrue(d["controller_facts"]["remote_logging_is_separate_from_controller_local_logs"])
        self.assertTrue(d["safety"]["notification_delivery_is_not_equivalent_to_local_log_persistence"])
        self.assertTrue(d["safety"]["support_exports_require_masking_or_sanitization"])
        self.assertEqual(d["safety"]["unknown_feature_or_delivery_support"],"NOT_SUPPORTED_UNVERIFIED")

if __name__=="__main__": unittest.main()
