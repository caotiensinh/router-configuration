import unittest
from pathlib import Path

from router_configuration.vendors.cisco.acceptance_dispatch_boundary_audit import (
    CiscoAcceptanceDispatchBoundaryError,
    audit_dispatch_boundary,
)


DISPATCHER_FIXTURE = '''
"acceptance-dispatch/**"
"acceptance/requests/*.json"
permissions:
  contents: read
  actions: write
validate_dispatch_request
expected_source_sha
dispatch_request_sha256
'''
C03_FIXTURE = '''
workflow_dispatch:
  inputs:
    expected_source_sha:
      required: true
EXPECTED_SOURCE_SHA
before network access
if: github.event_name == 'workflow_dispatch'
production_write_authorized
'''
C04_FIXTURE = C03_FIXTURE + '\nrequest_method_scope"] == ["GET"]\n'


class CiscoAcceptanceDispatchBoundaryAuditTests(unittest.TestCase):
    def test_closed_fixture_passes_and_remains_non_authorizing(self):
        result = audit_dispatch_boundary(
            dispatcher_text=DISPATCHER_FIXTURE,
            c03_text=C03_FIXTURE,
            c04_text=C04_FIXTURE,
        )
        self.assertTrue(result["target_source_pins_verified"])
        self.assertTrue(result["c04_get_only_boundary_verified"])
        self.assertFalse(result["production_write_authorized"])

    def test_write_surface_fails_closed(self):
        with self.assertRaisesRegex(CiscoAcceptanceDispatchBoundaryError, "crossed read-only boundary"):
            audit_dispatch_boundary(
                dispatcher_text=DISPATCHER_FIXTURE + "\ncontents: write\n",
                c03_text=C03_FIXTURE,
                c04_text=C04_FIXTURE,
            )

    def test_converged_repository_boundary_when_files_are_present(self):
        dispatcher = Path(".github/workflows/cisco-acceptance-dispatcher.yml")
        if not dispatcher.exists():
            self.skipTest("dispatcher is integrated only at convergence")
        result = audit_dispatch_boundary(
            dispatcher_text=dispatcher.read_text(encoding="utf-8"),
            c03_text=Path(".github/workflows/cisco-netconf-live-readonly.yml").read_text(encoding="utf-8"),
            c04_text=Path(".github/workflows/cisco-restconf-live-readonly.yml").read_text(encoding="utf-8"),
        )
        self.assertFalse(result["production_write_authorized"])


if __name__ == "__main__":
    unittest.main()
