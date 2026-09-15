import json
import unittest

from tests.test_cisco_virtual_lab_acceptance import approval, live_fixture
from router_configuration.vendors.cisco.virtual_lab_evidence_ingest import (
    CiscoVirtualLabIngestError,
    ingest_cisco_virtual_lab_evidence_json,
)


class CiscoVirtualLabEvidenceIngestTests(unittest.TestCase):
    def _raw(self, payload=None) -> str:
        return json.dumps(payload if payload is not None else live_fixture(), sort_keys=True)

    def test_valid_candidate_artifact_is_sanitized_but_not_repository_accepted(self):
        first = ingest_cisco_virtual_lab_evidence_json(self._raw(), approval=approval())
        second = ingest_cisco_virtual_lab_evidence_json(self._raw(), approval=approval())
        self.assertEqual(first["ingest_record_sha256"], second["ingest_record_sha256"])
        self.assertTrue(first["candidate_bundle_claims_live_virtual_iosxe"])
        self.assertTrue(first["candidate_bundle_claims_c09_complete"])
        self.assertFalse(first["repository_live_evidence_accepted"])
        self.assertFalse(first["repository_c09_complete"])
        self.assertFalse(first["physical_hardware_claimed"])
        self.assertFalse(first["production_writer_available"])
        self.assertFalse(first["production_write_authorized"])

    def test_bytes_must_be_strict_utf8(self):
        with self.assertRaisesRegex(CiscoVirtualLabIngestError, "strict UTF-8"):
            ingest_cisco_virtual_lab_evidence_json(b"{\xff}", approval=approval())

    def test_json_root_must_be_object(self):
        with self.assertRaisesRegex(CiscoVirtualLabIngestError, "root"):
            ingest_cisco_virtual_lab_evidence_json("[]", approval=approval())

    def test_malformed_json_fails_closed(self):
        with self.assertRaisesRegex(CiscoVirtualLabIngestError, "valid JSON"):
            ingest_cisco_virtual_lab_evidence_json("{broken", approval=approval())

    def test_duplicate_json_keys_are_rejected_before_semantic_validation(self):
        with self.assertRaisesRegex(CiscoVirtualLabIngestError, "duplicate JSON key"):
            ingest_cisco_virtual_lab_evidence_json('{"schema_version":"a","schema_version":"b"}', approval=approval())

    def test_unknown_top_level_field_is_rejected(self):
        payload = live_fixture()
        payload["unexpected"] = "value"
        with self.assertRaisesRegex(CiscoVirtualLabIngestError, "unknown C09 top-level"):
            ingest_cisco_virtual_lab_evidence_json(self._raw(payload), approval=approval())

    def test_missing_top_level_field_is_rejected(self):
        payload = live_fixture()
        payload.pop("source_run_id")
        with self.assertRaisesRegex(CiscoVirtualLabIngestError, "missing C09 top-level"):
            ingest_cisco_virtual_lab_evidence_json(self._raw(payload), approval=approval())

    def test_sensitive_nested_keys_are_rejected(self):
        payload = live_fixture()
        payload["scenarios"][0]["token"] = "must-not-enter-evidence"
        with self.assertRaisesRegex(CiscoVirtualLabIngestError, "sensitive key"):
            ingest_cisco_virtual_lab_evidence_json(self._raw(payload), approval=approval())

    def test_oversized_artifact_is_rejected(self):
        with self.assertRaisesRegex(CiscoVirtualLabIngestError, "bounded ingestion limit"):
            ingest_cisco_virtual_lab_evidence_json("x" * (128 * 1024 + 1), approval=approval())

    def test_empty_artifact_is_rejected(self):
        with self.assertRaisesRegex(CiscoVirtualLabIngestError, "bounded ingestion limit"):
            ingest_cisco_virtual_lab_evidence_json("", approval=approval())

    def test_semantic_mismatch_is_delegated_to_existing_c09_validator(self):
        payload = live_fixture()
        payload["target_id"] = "wrong-target"
        with self.assertRaisesRegex(ValueError, "target differs"):
            ingest_cisco_virtual_lab_evidence_json(self._raw(payload), approval=approval())


if __name__ == "__main__":
    unittest.main()
