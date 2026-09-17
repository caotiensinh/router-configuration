import json
import unittest

from tests.test_cisco_virtual_lab_acceptance import approval, live_fixture
from router_configuration.vendors.cisco.virtual_lab_evidence_ingest import (
    ingest_cisco_virtual_lab_evidence_json,
)
from router_configuration.vendors.cisco.virtual_lab_evidence_replay import (
    CiscoVirtualLabReplayError,
    verify_c09_ingest_replay,
)


class CiscoVirtualLabEvidenceReplayTests(unittest.TestCase):
    def _raw(self):
        return json.dumps(live_fixture(), sort_keys=True)

    def test_exact_raw_artifact_replays_to_same_ingest_record(self):
        raw = self._raw()
        ingest = ingest_cisco_virtual_lab_evidence_json(raw, approval=approval())
        first = verify_c09_ingest_replay(raw, ingest_record=ingest, approval=approval())
        second = verify_c09_ingest_replay(raw, ingest_record=ingest, approval=approval())
        self.assertEqual(first, second)
        self.assertTrue(first["exact_raw_replay_verified"])
        self.assertEqual(first["ingest_record_sha256"], ingest["ingest_record_sha256"])
        self.assertFalse(first["repository_live_evidence_accepted"])
        self.assertFalse(first["repository_c09_complete"])
        self.assertFalse(first["production_write_authorized"])

    def test_tampered_ingest_digest_is_rejected(self):
        raw = self._raw()
        ingest = ingest_cisco_virtual_lab_evidence_json(raw, approval=approval())
        ingest["ingest_record_sha256"] = "0" * 64
        with self.assertRaisesRegex(CiscoVirtualLabReplayError, "ingest_record_sha256"):
            verify_c09_ingest_replay(raw, ingest_record=ingest, approval=approval())

    def test_extra_field_and_self_promotion_are_rejected(self):
        raw = self._raw()
        ingest = ingest_cisco_virtual_lab_evidence_json(raw, approval=approval())
        ingest["extra"] = True
        with self.assertRaisesRegex(CiscoVirtualLabReplayError, "field set"):
            verify_c09_ingest_replay(raw, ingest_record=ingest, approval=approval())

        ingest = ingest_cisco_virtual_lab_evidence_json(raw, approval=approval())
        ingest["repository_c09_complete"] = True
        with self.assertRaisesRegex(CiscoVirtualLabReplayError, "safety boundary"):
            verify_c09_ingest_replay(raw, ingest_record=ingest, approval=approval())

    def test_changed_raw_artifact_cannot_replay_against_old_record(self):
        raw = self._raw()
        ingest = ingest_cisco_virtual_lab_evidence_json(raw, approval=approval())
        payload = live_fixture()
        payload["source_run_id"] = "another-run"
        changed = json.dumps(payload, sort_keys=True)
        with self.assertRaises((CiscoVirtualLabReplayError, ValueError)):
            verify_c09_ingest_replay(changed, ingest_record=ingest, approval=approval())


if __name__ == "__main__":
    unittest.main()
