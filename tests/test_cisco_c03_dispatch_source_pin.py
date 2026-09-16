import unittest
from pathlib import Path


WORKFLOW = Path(".github/workflows/cisco-netconf-live-readonly.yml")


class CiscoC03DispatchSourcePinTests(unittest.TestCase):
    def test_workflow_requires_exact_expected_source_sha(self):
        text = WORKFLOW.read_text(encoding="utf-8")
        self.assertIn("expected_source_sha:", text)
        self.assertIn("required: true", text)
        self.assertIn("EXPECTED_SOURCE_SHA", text)
        self.assertIn('if [ "$SOURCE_SHA" != "$EXPECTED_SOURCE_SHA" ]', text)
        self.assertIn("before network access", text)

    def test_live_job_remains_dispatch_only_and_readonly(self):
        text = WORKFLOW.read_text(encoding="utf-8")
        self.assertIn("if: github.event_name == 'workflow_dispatch'", text)
        self.assertIn("production_write_authorized", text)
        self.assertIn("write_operations_performed", text)
        for forbidden in ("edit_config(", "commit(", "configure terminal", "write memory"):
            self.assertNotIn(forbidden, text)


if __name__ == "__main__":
    unittest.main()
