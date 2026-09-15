import unittest

from router_configuration.vendors.cisco.preproduction_boundary_audit import (
    CiscoPreproductionBoundaryAuditError,
    audit_preproduction_boundary,
)


class CiscoPreproductionBoundaryAuditTests(unittest.TestCase):
    def test_nested_safe_bundle_is_deterministic(self):
        artifacts = {
            "c06": {"c06_complete": False, "production_write_authorized": False},
            "c10": {
                "observation": {
                    "production_writer_available": False,
                    "production_write_authorized": False,
                }
            },
        }
        first = audit_preproduction_boundary(artifacts)
        second = audit_preproduction_boundary(artifacts)
        self.assertEqual(first, second)
        self.assertEqual(first["artifact_count"], 2)
        self.assertEqual(first["prohibited_write_surface_count"], 0)
        self.assertTrue(first["safe_for_convergence_review"])
        self.assertFalse(first["production_writer_available"])
        self.assertFalse(first["production_write_authorized"])
        self.assertEqual(len(first["audit_sha256"]), 64)

    def test_nested_write_authority_is_rejected(self):
        artifacts = {
            "c08": {
                "review": {
                    "apply_authorized": True,
                    "production_write_authorized": False,
                }
            }
        }
        with self.assertRaisesRegex(CiscoPreproductionBoundaryAuditError, "apply_authorized"):
            audit_preproduction_boundary(artifacts)

    def test_production_writer_surface_is_rejected(self):
        artifacts = {"c10": [{"production_writer_available": True}]}
        with self.assertRaisesRegex(CiscoPreproductionBoundaryAuditError, "production_writer_available"):
            audit_preproduction_boundary(artifacts)

    def test_empty_bundle_is_rejected(self):
        with self.assertRaisesRegex(CiscoPreproductionBoundaryAuditError, "must not be empty"):
            audit_preproduction_boundary({})


if __name__ == "__main__":
    unittest.main()
