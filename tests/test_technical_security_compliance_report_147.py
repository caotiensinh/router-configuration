import unittest

from router_configuration.technical_security_compliance_report import (
    SecurityComplianceReportError,
    build_technical_security_compliance_report,
)


FINDING = {
    "framework": "NIST-CSF",
    "control_id": "PR.AA",
    "requirement": "Access is limited to authorized users and services.",
    "status": "VERIFIED",
    "vendor_implementation": "Technical mapping to verified Omada access-control evidence.",
    "evidence_refs": ["evidence://omada/access-control/001"],
}


class TechnicalSecurityComplianceReportTests(unittest.TestCase):
    def test_verified_report_is_explicitly_non_certifying(self):
        report = build_technical_security_compliance_report(
            source_main_sha="1" * 40,
            environment_id="rd-lab",
            generated_at="2026-09-17T14:00:00Z",
            findings=[FINDING],
            known_restrictions=["No organization-wide certification claim."],
        ).as_dict()
        self.assertEqual(report["report_scope"], "TECHNICAL_CONTROL_MAPPING_ONLY")
        self.assertFalse(report["certification_claimed"])
        self.assertFalse(report["organizational_compliance_claimed"])
        self.assertEqual(report["summary"]["VERIFIED"], 1)

    def test_verified_finding_without_evidence_fails_closed(self):
        finding = dict(FINDING, evidence_refs=[])
        with self.assertRaises(SecurityComplianceReportError):
            build_technical_security_compliance_report(
                source_main_sha="1" * 40,
                environment_id="rd-lab",
                generated_at="2026-09-17T14:00:00Z",
                findings=[finding],
                known_restrictions=[],
            )

    def test_not_applicable_requires_rationale(self):
        finding = dict(FINDING, status="NOT_APPLICABLE", evidence_refs=[], rationale="")
        with self.assertRaises(SecurityComplianceReportError):
            build_technical_security_compliance_report(
                source_main_sha="1" * 40,
                environment_id="rd-lab",
                generated_at="2026-09-17T14:00:00Z",
                findings=[finding],
                known_restrictions=[],
            )

    def test_output_hash_is_deterministic(self):
        kwargs = {
            "source_main_sha": "1" * 40,
            "environment_id": "rd-lab",
            "generated_at": "2026-09-17T14:00:00Z",
            "findings": [FINDING],
            "known_restrictions": ["restriction-b", "restriction-a"],
        }
        a = build_technical_security_compliance_report(**kwargs).as_dict()
        b = build_technical_security_compliance_report(**kwargs).as_dict()
        self.assertEqual(a["report_sha256"], b["report_sha256"])

    def test_secret_bearing_material_is_rejected(self):
        finding = dict(FINDING, password="forbidden")
        with self.assertRaises(SecurityComplianceReportError):
            build_technical_security_compliance_report(
                source_main_sha="1" * 40,
                environment_id="rd-lab",
                generated_at="2026-09-17T14:00:00Z",
                findings=[finding],
                known_restrictions=[],
            )


if __name__ == "__main__":
    unittest.main()
