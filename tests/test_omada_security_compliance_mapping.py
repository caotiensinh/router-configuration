import json
import unittest
from pathlib import Path

ROOT = Path(__file__).parents[1]

class OmadaSecurityComplianceMappingTests(unittest.TestCase):
    def test_mapping_is_evidence_bound_and_never_claims_certification(self):
        data=json.loads((ROOT/"artifacts"/"OMADA_SECURITY_COMPLIANCE_MAPPING_SCHEMA.json").read_text(encoding="utf-8"))
        self.assertEqual(data["task"], "10.10")
        self.assertTrue(data["mapping_semantics"]["mapping_is_not_certification"])
        self.assertTrue(data["mapping_semantics"]["licensed_or_nonpublic_control_text_must_not_be_invented"])
        self.assertEqual(data["fail_closed"]["mapping_as_compliance_claim"], "REJECTED")
        self.assertEqual(data["fail_closed"]["missing_evidence"], "MAPPING_UNVERIFIED")
        claims={item["framework"]:item["claim"] for item in data["supported_public_mappings"]}
        self.assertEqual(claims["ISO/IEC 27001:2022"], "licensed_control_text_required_for_exact_clause_mapping")
        kb=(ROOT/"knowledge"/"OMADA_SECURITY_COMPLIANCE_MAPPING_KB.md").read_text(encoding="utf-8")
        self.assertIn("not a certification", kb)
        self.assertIn("MAPPING_UNVERIFIED", kb)

if __name__ == "__main__":
    unittest.main()
