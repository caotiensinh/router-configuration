import unittest
from pathlib import Path


WORKFLOW = Path(".github/workflows/cisco-restconf-live-readonly.yml")


class CiscoC04DispatchSourcePinTests(unittest.TestCase):
    def test_workflow_requires_exact_expected_source_sha(self):
        text = WORKFLOW.read_text(encoding="utf-8")
        self.assertIn("expected_source_sha:", text)
        self.assertIn("required: true", text)
        self.assertIn("EXPECTED_SOURCE_SHA", text)
        self.assertIn('if [ "$SOURCE_SHA" != "$EXPECTED_SOURCE_SHA" ]', text)
        self.assertIn("before network access", text)

    def test_live_job_remains_dispatch_only_and_get_only(self):
        text = WORKFLOW.read_text(encoding="utf-8")
        self.assertIn("if: github.event_name == 'workflow_dispatch'", text)
        self.assertIn("request_method_scope", text)
        self.assertIn('["GET"]', text)
        self.assertIn("tls_certificate_verification_required", text)
        for forbidden in ("PATCH", "POST", "PUT", "DELETE"):
            self.assertNotIn(f'request_method_scope"] == ["{forbidden}"]', text)


if __name__ == "__main__":
    unittest.main()
