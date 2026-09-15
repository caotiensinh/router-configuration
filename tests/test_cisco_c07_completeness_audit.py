import copy
import unittest

from router_configuration.vendors.cisco.c07_completeness_audit import (
    CiscoC07CompletenessAuditError,
    audit_c07_catalog,
    audit_current_c07_catalog,
)
from router_configuration.vendors.cisco.desired_state import load_desired_state_catalog


class CiscoC07CompletenessAuditTests(unittest.TestCase):
    def test_current_catalog_is_consistent_and_non_promoting(self):
        result = audit_current_c07_catalog()
        self.assertTrue(result["catalog_consistent"])
        self.assertEqual(result["bounded_feature_count"], 3)
        self.assertEqual(
            result["admitted_feature_ids"],
            ["interface.description.set", "interface.mtu.set", "interface.shutdown.set"],
        )
        self.assertIn("interface.shutdown.remove", result["unadmitted_operations"])
        self.assertFalse(result["c07_complete"])
        self.assertFalse(result["apply_authorized"])
        self.assertFalse(result["production_write_authorized"])
        self.assertEqual(len(result["audit_sha256"]), 64)

    def test_feature_drift_is_rejected(self):
        catalog = copy.deepcopy(load_desired_state_catalog())
        catalog["features"] = catalog["features"][:-1]
        with self.assertRaisesRegex(CiscoC07CompletenessAuditError, "feature set drift"):
            audit_c07_catalog(catalog)

    def test_safety_flag_drift_is_rejected(self):
        catalog = copy.deepcopy(load_desired_state_catalog())
        catalog["production_write_authorized"] = True
        with self.assertRaisesRegex(CiscoC07CompletenessAuditError, "safety boundary"):
            audit_c07_catalog(catalog)


if __name__ == "__main__":
    unittest.main()
