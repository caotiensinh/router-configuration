import unittest

from router_configuration.vendors.cisco.acceptance_dispatch_correlation import (
    CiscoAcceptanceDispatchCorrelationError,
    correlate_live_evidence,
)


class CiscoAcceptanceDispatchCorrelationTests(unittest.TestCase):
    def c03(self):
        return {
            "schema_version": "cisco-c03-live-evidence/1",
            "source_sha": "1" * 40,
            "c03_complete": True,
            "hostkey_verified": True,
            "write_operations_performed": False,
            "production_write_authorized": False,
        }

    def c04(self):
        return {
            "schema_version": "cisco-c04-live-restconf-evidence/2",
            "source_sha": "1" * 40,
            "c04_complete": True,
            "result": "live_readonly_admitted",
            "request_method_scope": ["GET"],
            "write_operations_performed": False,
            "production_write_authorized": False,
        }

    def test_c03_and_c04_correlation_remain_non_promoting(self):
        for stage, evidence in (("c03", self.c03()), ("c04", self.c04())):
            result = correlate_live_evidence(
                evidence,
                stage=stage,
                dispatch_request_id=f"ACC-{stage.upper()}-001",
                dispatch_request_sha256="2" * 64,
                expected_source_sha="1" * 40,
            )
            self.assertTrue(result["source_continuity_verified"])
            self.assertTrue(result["read_only_live_evidence_verified"])
            self.assertFalse(result["repository_evidence_accepted"])
            self.assertFalse(result["acceptance_stage_complete"])
            self.assertFalse(result["production_write_authorized"])

    def test_source_mismatch_or_write_claim_fails_closed(self):
        with self.assertRaisesRegex(CiscoAcceptanceDispatchCorrelationError, "source continuity"):
            correlate_live_evidence(
                self.c03(),
                stage="c03",
                dispatch_request_id="ACC-C03-002",
                dispatch_request_sha256="3" * 64,
                expected_source_sha="9" * 40,
            )

        item = self.c04()
        item["write_operations_performed"] = True
        with self.assertRaisesRegex(CiscoAcceptanceDispatchCorrelationError, "write operation"):
            correlate_live_evidence(
                item,
                stage="c04",
                dispatch_request_id="ACC-C04-002",
                dispatch_request_sha256="4" * 64,
                expected_source_sha="1" * 40,
            )


if __name__ == "__main__":
    unittest.main()
