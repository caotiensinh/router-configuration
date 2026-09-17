import unittest

from router_configuration.raw_source_version import RawSourceVersionError, bind_raw_source_version


def archive_entry():
    return {
        "source_id": "omada-guide-v6",
        "source_url": "https://support.omadanetworks.com/en/document/111217/",
        "retrieved_at": "2026-09-17T03:00:00+00:00",
        "archive_path": "raw/omada-guide-v6.raw",
        "state": "RAW_ARCHIVED_UNVERIFIED",
    }


class RawSourceVersion112Tests(unittest.TestCase):
    def test_first_version_hashes_exact_raw_bytes_deterministically(self):
        a = bind_raw_source_version(archive_entry=archive_entry(), raw_bytes=b"abc\n", version_ordinal=1).as_dict()
        b = bind_raw_source_version(archive_entry=archive_entry(), raw_bytes=b"abc\n", version_ordinal=1).as_dict()
        self.assertEqual(a, b)
        self.assertEqual(a["byte_length"], 4)
        self.assertEqual(a["hash_input"], "EXACT_RAW_BYTES")
        self.assertFalse(a["normalization_applied"])
        self.assertEqual(a["state"], "RAW_HASH_VERSION_BOUND")
        self.assertEqual(len(a["sha256"]), 64)

    def test_changed_bytes_create_contiguous_hash_chain(self):
        first = bind_raw_source_version(archive_entry=archive_entry(), raw_bytes=b"v1", version_ordinal=1).as_dict()
        second = bind_raw_source_version(
            archive_entry=archive_entry(), raw_bytes=b"v2", version_ordinal=2, previous_record=first
        ).as_dict()
        self.assertEqual(second["previous_sha256"], first["sha256"])
        self.assertEqual(second["supersedes_version_ordinal"], 1)
        self.assertNotEqual(second["sha256"], first["sha256"])

    def test_unchanged_bytes_or_noncontiguous_version_fail_closed(self):
        first = bind_raw_source_version(archive_entry=archive_entry(), raw_bytes=b"same", version_ordinal=1).as_dict()
        with self.assertRaises(RawSourceVersionError):
            bind_raw_source_version(archive_entry=archive_entry(), raw_bytes=b"same", version_ordinal=2, previous_record=first)
        with self.assertRaises(RawSourceVersionError):
            bind_raw_source_version(archive_entry=archive_entry(), raw_bytes=b"changed", version_ordinal=3, previous_record=first)

    def test_wrong_archive_state_and_secret_fields_are_rejected(self):
        bad = archive_entry()
        bad["state"] = "NORMALIZED"
        with self.assertRaises(RawSourceVersionError):
            bind_raw_source_version(archive_entry=bad, raw_bytes=b"x", version_ordinal=1)
        bad = archive_entry()
        bad["password"] = "plaintext"
        with self.assertRaises(RawSourceVersionError):
            bind_raw_source_version(archive_entry=bad, raw_bytes=b"x", version_ordinal=1)


if __name__ == "__main__":
    unittest.main()
