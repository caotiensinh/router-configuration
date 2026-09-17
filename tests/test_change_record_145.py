import unittest

from router_configuration.change_record import ChangeRecordError, build_change_record


SHA1 = "a" * 40
SHA256 = "b" * 64


def base_kwargs():
    return dict(
        change_id="chg-145-001",
        changeset_sha256=SHA256,
        planned_main_sha=SHA1,
        change_window="2026-09-17T12:00:00+09:00/2026-09-17T13:00:00+09:00",
        approval_evidence_ref="evidence://approval/1",
        pre_change_evidence_refs=["evidence://pre/1"],
        post_change_evidence_refs=["evidence://post/1"],
        outcome="VERIFIED",
    )


class ChangeRecord145Tests(unittest.TestCase):
    def test_change_record_is_deterministic_and_non_executable(self):
        a = build_change_record(**base_kwargs()).as_dict()
        b = build_change_record(**base_kwargs()).as_dict()
        self.assertEqual(a, b)
        self.assertFalse(a["secret_material_included"])
        self.assertFalse(a["transport_present"])
        self.assertFalse(a["apply_available"])
        self.assertFalse(a["production_writer_available"])
        self.assertFalse(a["write_authorized"])
        self.assertEqual(len(a["change_record_sha256"]), 64)

    def test_outcome_evidence_consistency_fails_closed(self):
        kwargs = base_kwargs()
        kwargs["post_change_evidence_refs"] = []
        with self.assertRaises(ChangeRecordError):
            build_change_record(**kwargs)

        kwargs = base_kwargs()
        kwargs["outcome"] = "ROLLED_BACK_VERIFIED"
        kwargs["rollback_evidence_refs"] = []
        with self.assertRaises(ChangeRecordError):
            build_change_record(**kwargs)

    def test_hardware_claim_requires_physical_evidence(self):
        kwargs = base_kwargs()
        kwargs["hardware_claim"] = True
        with self.assertRaises(ChangeRecordError):
            build_change_record(**kwargs)

        kwargs["physical_evidence_refs"] = ["evidence://physical/device-1"]
        record = build_change_record(**kwargs).as_dict()
        self.assertTrue(record["hardware_claim"])
        self.assertEqual(record["physical_evidence_refs"], ["evidence://physical/device-1"])

    def test_invalid_hash_or_main_sha_is_rejected(self):
        kwargs = base_kwargs()
        kwargs["changeset_sha256"] = "not-a-digest"
        with self.assertRaises(ChangeRecordError):
            build_change_record(**kwargs)
        kwargs = base_kwargs()
        kwargs["planned_main_sha"] = "not-a-sha"
        with self.assertRaises(ChangeRecordError):
            build_change_record(**kwargs)


if __name__ == "__main__":
    unittest.main()
