import copy
import unittest

from router_configuration.vendors.cisco.desired_state import load_desired_state_catalog
from router_configuration.vendors.cisco.physical_acceptance import load_physical_acceptance_catalog
from router_configuration.vendors.cisco.source_catalog_audit import (
    CiscoSourceCatalogAuditError,
    _audit_catalogs,
    audit_current_cisco_source_catalogs,
)
from router_configuration.vendors.cisco.switch_state import load_switch_state_catalog


class CiscoSourceCatalogAuditTests(unittest.TestCase):
    def catalogs(self):
        return (
            load_desired_state_catalog(),
            load_switch_state_catalog(),
            load_physical_acceptance_catalog(),
        )

    def test_current_catalogs_are_consistent_and_non_promoting(self):
        first = audit_current_cisco_source_catalogs()
        second = audit_current_cisco_source_catalogs()
        self.assertEqual(first, second)
        self.assertTrue(first.provenance_consistent)
        self.assertTrue(first.safety_boundaries_closed)
        self.assertEqual(first.documentation_trains, ("17.18", "26"))
        self.assertFalse(first.c06_complete)
        self.assertFalse(first.c07_complete)
        self.assertFalse(first.c11_complete)
        self.assertFalse(first.physical_device_verified)
        self.assertFalse(first.production_write_authorized)
        self.assertEqual(len(first.audit_sha256), 64)

    def test_vendor_os_drift_is_rejected(self):
        desired, switch, physical = self.catalogs()
        physical = copy.deepcopy(physical)
        physical["vendor"] = "Other"
        with self.assertRaisesRegex(CiscoSourceCatalogAuditError, "vendor/OS"):
            _audit_catalogs(desired, switch, physical)

    def test_documentation_train_drift_is_rejected(self):
        desired, switch, physical = self.catalogs()
        switch = copy.deepcopy(switch)
        switch["documentation_trains"].pop("26")
        with self.assertRaisesRegex(CiscoSourceCatalogAuditError, "train set drift"):
            _audit_catalogs(desired, switch, physical)

    def test_yangmodels_pin_drift_is_rejected(self):
        desired, switch, physical = self.catalogs()
        switch = copy.deepcopy(switch)
        switch["schema_provenance"]["yangmodels_commit"] = "f" * 40
        with self.assertRaisesRegex(CiscoSourceCatalogAuditError, "source pin drift"):
            _audit_catalogs(desired, switch, physical)

    def test_c07_safety_boundary_drift_is_rejected(self):
        desired, switch, physical = self.catalogs()
        desired = copy.deepcopy(desired)
        desired["production_write_authorized"] = True
        with self.assertRaisesRegex(CiscoSourceCatalogAuditError, "safety invariant drift"):
            _audit_catalogs(desired, switch, physical)

    def test_c06_live_gate_drift_is_rejected(self):
        desired, switch, physical = self.catalogs()
        switch = copy.deepcopy(switch)
        switch["live_state_evidence_required_for_c06"] = False
        with self.assertRaisesRegex(CiscoSourceCatalogAuditError, "live-state evidence gate"):
            _audit_catalogs(desired, switch, physical)

    def test_c11_human_boundary_drift_is_rejected(self):
        desired, switch, physical = self.catalogs()
        physical = copy.deepcopy(physical)
        physical["human_attestation_required"] = False
        with self.assertRaisesRegex(CiscoSourceCatalogAuditError, "human/read-only"):
            _audit_catalogs(desired, switch, physical)

    def test_catalog_digest_changes_are_visible(self):
        desired, switch, physical = self.catalogs()
        baseline = _audit_catalogs(desired, switch, physical)
        desired2 = copy.deepcopy(desired)
        desired2["audit_note"] = "semantically-neutral-digest-change"
        changed = _audit_catalogs(desired2, switch, physical)
        self.assertNotEqual(baseline.desired_state_catalog_sha256, changed.desired_state_catalog_sha256)
        self.assertNotEqual(baseline.audit_sha256, changed.audit_sha256)


if __name__ == "__main__":
    unittest.main()
