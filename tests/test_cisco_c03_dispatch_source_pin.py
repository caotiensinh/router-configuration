import unittest
from pathlib import Path


WORKFLOW = Path(".github/workflows/cisco-netconf-live-readonly.yml")


class CiscoC03DispatchSourcePinTests(unittest.TestCase):
    def test_workflow_requires_exact_expected_source_sha(self):
        text = WORKFLOW.read_text(encoding="utf-8")
        self.assertIn("expected_source_sha:", text)
        self.assertIn("required: true", text)
        self.assertIn("EXPECTED_SOURCE_SHA", text)
        self.assertIn("git rev-parse HEAD", text)
        self.assertIn('if [ "$observed_source_sha" != "$EXPECTED_SOURCE_SHA" ]', text)
        self.assertIn("before network access", text)
        self.assertIn("ref: ${{ inputs.expected_source_sha }}", text)

    def test_live_job_requires_explicit_manual_or_reusable_execution_and_is_readonly(self):
        text = WORKFLOW.read_text(encoding="utf-8")
        self.assertIn("workflow_call:", text)
        self.assertIn("live_execution_requested:", text)
        self.assertIn("inputs.live_execution_requested == true", text)
        self.assertIn("github.event_name == 'workflow_dispatch'", text)
        self.assertIn("runs-on: self-hosted", text)
        self.assertIn("aiserver-router-configuration", text)
        self.assertIn("production_write_authorized", text)
        self.assertIn("write_operations_performed", text)
        for forbidden in ("edit_config(", "commit(", "configure terminal", "write memory"):
            self.assertNotIn(forbidden, text)


if __name__ == "__main__":
    unittest.main()
