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
        self.assertIn("Verify target ref remains at exact requested source SHA", text)
        self.assertIn("production_write_authorized", text)

    def test_c03_uses_owner_preserving_reusable_call_with_least_privilege_secrets(self):
        text = WORKFLOW.read_text(encoding="utf-8")
        self.assertIn("c03-live:", text)
        self.assertIn("if: needs.validate.outputs.stage == 'c03'", text)
        self.assertIn("uses: ./.github/workflows/cisco-netconf-live-readonly.yml", text)
        self.assertIn("live_execution_requested: true", text)
        for name in (
            "CISCO_NETCONF_HOST",
            "CISCO_NETCONF_PORT",
            "CISCO_NETCONF_USERNAME",
            "CISCO_NETCONF_PASSWORD",
            "CISCO_NETCONF_HOSTKEY_B64",
        ):
            self.assertIn(f"{name}: ${{{{ secrets.{name} }}}}", text)
        self.assertNotIn("secrets: inherit", text)

    def test_c04_retains_returned_run_details_for_correlation(self):
        text = WORKFLOW.read_text(encoding="utf-8")
        self.assertIn("c04-dispatch:", text)
        self.assertIn("if: needs.validate.outputs.stage == 'c04'", text)
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
            "CISCO_RESTCONF_PASSWORD",
        )
        self.assertEqual([token for token in forbidden if token in text], [])


if __name__ == "__main__":
    unittest.main()
