import unittest

from router_configuration.raw_source_versioning import RawSourceVersionError, bind_raw_source_version


class RawSourceVersioning112Tests(unittest.TestCase):
    def test_first_version_hashes_exact_raw_bytes(self):
        record = bind_raw_source_version(
            source_id="guide",
            archive_path="raw/guide.raw",
            raw_bytes=b"abc\n",
        )
        self.assertEqual(record.version_ordinal, 1)
        self.assertEqual(record.byte_length, 4)
        self.assertEqual(record.sha256, "edeaaff3f1774ad2888673770c6d64097e391bc362d7d6fb34982ddf0efd18cb")
        self.assertIsNone(record.previous_sha256)
        self.assertEqual(record.state, "RAW_HASH_VERSION_BOUND")

    def test_changed_raw_bytes_create_next_hash_chained_version(self):
        first = bind_raw_source_version(
            source_id="guide", archive_path="raw/guide.raw", raw_bytes=b"v1"
        )
        second = bind_raw_source_version(
            source_id="guide", archive_path="raw/guide.raw", raw_bytes=b"v2", prior_records=[first]
        )
        self.assertEqual(second.version_ordinal, 2)
        self.assertEqual(second.previous_sha256, first.sha256)
        self.assertNotEqual(second.sha256, first.sha256)

    def test_identical_latest_content_is_not_duplicate_version(self):
        first = bind_raw_source_version(
            source_id="guide", archive_path="raw/guide.raw", raw_bytes=b"same"
        )
        with self.assertRaises(RawSourceVersionError):
            bind_raw_source_version(
                source_id="guide", archive_path="raw/guide.raw", raw_bytes=b"same", prior_records=[first]
            )

    def test_broken_chain_or_unsafe_archive_path_fails_closed(self):
        first = bind_raw_source_version(
            source_id="guide", archive_path="raw/guide.raw", raw_bytes=b"v1"
        )
        broken = type(first)(
            source_id=first.source_id,
            archive_path=first.archive_path,
            byte_length=first.byte_length,
            sha256=first.sha256,
            version_ordinal=2,
            previous_sha256="0" * 64,
        )
        with self.assertRaises(RawSourceVersionError):
            bind_raw_source_version(
                source_id="guide", archive_path="raw/guide.raw", raw_bytes=b"v3", prior_records=[broken]
            )
        with self.assertRaises(RawSourceVersionError):
            bind_raw_source_version(source_id="guide", archive_path="../escape.raw", raw_bytes=b"v1")


if __name__ == "__main__":
    unittest.main()
