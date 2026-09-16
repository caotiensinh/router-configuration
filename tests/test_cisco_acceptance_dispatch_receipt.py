import unittest

from router_configuration.vendors.cisco.acceptance_dispatch_receipt import (
    CiscoAcceptanceDispatchReceiptError,
    verify_dispatch_receipt,
)


class CiscoAcceptanceDispatchReceiptTests(unittest.TestCase):
    def receipt(self):
        return {
            "schema_version": "cisco-acceptance-dispatch-receipt/1",
            "request_id": "ACC-C03-001",
            "request_sha256": "1" * 64,
            "stage": "c03",
            "target_ref": "feat/cisco-iosxe-router-switch-domain-20260915",
            "expected_source_sha": "2" * 40,
            "observed_source_sha": "2" * 40,
            "workflow_file": "cisco-netconf-live-readonly.yml",
            "dispatch_status": "dispatched",
            "http_status": 204,
            "production_write_authorized": False,
        }

    def test_successful_receipt_is_non_promoting(self):
        result = verify_dispatch_receipt(
            self.receipt(),
            expected_request_sha256="1" * 64,
            expected_source_sha="2" * 40,
        )
        self.assertTrue(result["dispatch_api_accepted"])
        self.assertFalse(result["live_device_evidence_observed"])
        self.assertFalse(result["acceptance_stage_complete"])
        self.assertFalse(result["production_write_authorized"])

    def test_moved_source_or_wrong_workflow_fails_closed(self):
        item = self.receipt()
        item["observed_source_sha"] = "3" * 40
        with self.assertRaisesRegex(CiscoAcceptanceDispatchReceiptError, "source continuity"):
            verify_dispatch_receipt(item, expected_request_sha256="1" * 64, expected_source_sha="2" * 40)

        item = self.receipt()
        item["workflow_file"] = "cisco-recovery-observation.yml"
        with self.assertRaisesRegex(CiscoAcceptanceDispatchReceiptError, "stage/workflow"):
            verify_dispatch_receipt(item, expected_request_sha256="1" * 64, expected_source_sha="2" * 40)


if __name__ == "__main__":
    unittest.main()
