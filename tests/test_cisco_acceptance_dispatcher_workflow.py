import unittest
from pathlib import Path


WORKFLOW = Path(".github/workflows/cisco-acceptance-dispatcher.yml")


class CiscoAcceptanceDispatcherWorkflowTests(unittest.TestCase):
    def test_dispatcher_is_request_branch_scoped_and_read_only_staged(self):
        text = WORKFLOW.read_text(encoding="utf-8")
        self.assertIn('"acceptance-dispatch/**"', text)
        self.assertIn('"acceptance/requests/*.json"', text)
        self.assertIn("actions: write", text)
        self.assertIn("contents: read", text)
        self.assertNotIn("contents: write", text)
        self.assertIn("validate_dispatch_request", text)
        self.assertIn("expected_source_sha", text)
        self.assertIn("dispatch_request_sha256", text)
        self.assertIn("production_write_authorized", text)

    def test_dispatcher_requires_returned_run_details_for_correlation(self):
        text = WORKFLOW.read_text(encoding="utf-8")
        self.assertIn('"return_run_details": True', text)
        self.assertIn("if status != 200", text)
        self.assertIn('dispatch_payload.get("workflow_run_id")', text)
        self.assertIn('receipt["workflow_run_id"]', text)
        self.assertIn('receipt["run_url"]', text)
        self.assertIn('receipt["html_url"]', text)
        self.assertIn("cisco-acceptance-dispatch-receipt/2", text)
        self.assertNotIn("accepted_dispatch_statuses", text)

    def test_dispatcher_has_no_device_or_write_executor_surface(self):
        text = WORKFLOW.read_text(encoding="utf-8")
        forbidden = (
            "ncclient",
            "edit-config",
            "edit_config(",
            "commit confirmed",
            "write memory",
            "configure terminal",
            "CISCO_NETCONF_PASSWORD",
            "CISCO_RESTCONF_PASSWORD",
        )
        self.assertEqual([token for token in forbidden if token in text], [])


if __name__ == "__main__":
    unittest.main()
