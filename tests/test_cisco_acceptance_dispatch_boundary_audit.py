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
Verify target ref remains at exact requested source SHA
c03-live:
  if: needs.validate.outputs.stage == 'c03'
  uses: ./.github/workflows/cisco-netconf-live-readonly.yml
  with:
    live_execution_requested: true
  secrets:
    CISCO_NETCONF_PASSWORD: ${{ secrets.CISCO_NETCONF_PASSWORD }}
c04-dispatch:
  if: needs.validate.outputs.stage == 'c04'
'''
C03_FIXTURE = '''
workflow_call:
  inputs:
    expected_source_sha:
      required: true
    live_execution_requested:
      required: true
workflow_dispatch:
  inputs:
    expected_source_sha:
      required: true
EXPECTED_SOURCE_SHA
before network access
if: github.event_name == 'workflow_dispatch' || inputs.live_execution_requested == true
runs-on: self-hosted
aiserver-router-configuration
git rev-parse HEAD
ref: ${{ inputs.expected_source_sha }}
production_write_authorized
'''
C04_FIXTURE = '''
workflow_dispatch:
  inputs:
    expected_source_sha:
      required: true
EXPECTED_SOURCE_SHA
before network access
if: github.event_name == 'workflow_dispatch'
production_write_authorized
request_method_scope"] == ["GET"]
'''


class CiscoAcceptanceDispatchBoundaryAuditTests(unittest.TestCase):
    def test_closed_fixture_passes_and_remains_non_authorizing(self):
        result = audit_dispatch_boundary(
            dispatcher_text=DISPATCHER_FIXTURE,
            c03_text=C03_FIXTURE,
            c04_text=C04_FIXTURE,
        )
        self.assertTrue(result["target_source_pins_verified"])
        self.assertTrue(result["c03_owner_preserving_reusable_call_verified"])
        self.assertTrue(result["c03_reusable_owner_gate_path_verified"])
        self.assertTrue(result["c04_get_only_boundary_verified"])
        self.assertFalse(result["production_write_authorized"])

    def test_write_or_broad_secret_surface_fails_closed(self):
        for forbidden in ("contents: write", "secrets: inherit"):
            with self.subTest(forbidden=forbidden):
                with self.assertRaisesRegex(CiscoAcceptanceDispatchBoundaryError, "crossed read-only boundary"):
                    audit_dispatch_boundary(
                        dispatcher_text=DISPATCHER_FIXTURE + f"\n{forbidden}\n",
                        c03_text=C03_FIXTURE,
                        c04_text=C04_FIXTURE,
                    )

    def test_c03_without_reusable_owner_gate_markers_fails_closed(self):
        with self.assertRaisesRegex(CiscoAcceptanceDispatchBoundaryError, "c03 reusable owner-gated"):
            audit_dispatch_boundary(
                dispatcher_text=DISPATCHER_FIXTURE,
                c03_text=C03_FIXTURE.replace("workflow_call:", "workflow_run:"),
                c04_text=C04_FIXTURE,
            )

    def test_dispatcher_without_owner_preserving_c03_call_fails_closed(self):
        with self.assertRaisesRegex(CiscoAcceptanceDispatchBoundaryError, "dispatcher"):
            audit_dispatch_boundary(
                dispatcher_text=DISPATCHER_FIXTURE.replace(
                    "uses: ./.github/workflows/cisco-netconf-live-readonly.yml",
                    "uses: actions/checkout@v4",
                ),
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
