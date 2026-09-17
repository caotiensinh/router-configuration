import tempfile
import unittest
from pathlib import Path

from router_configuration.raw_document_archive import RawDocumentArchiveError, archive_raw_document


class RawDocumentArchive111Tests(unittest.TestCase):
    def _archive(self, root: Path, **overrides):
        kwargs = dict(
            root=root,
            source_id="omada-guide-v6",
            source_url="https://support.omadanetworks.com/en/document/111217/",
            retrieved_at="2026-09-17T03:00:00+00:00",
            media_type="application/pdf",
            authority_scope="Omada Controller V6 guide",
            raw_bytes=b"official-raw-bytes",
        )
        kwargs.update(overrides)
        return archive_raw_document(**kwargs)

    def test_raw_bytes_are_persisted_once_without_normalization(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            entry = self._archive(root)
            self.assertEqual(entry.state, "RAW_ARCHIVED_UNVERIFIED")
            self.assertEqual(entry.archive_path, "raw/omada-guide-v6.raw")
            self.assertEqual((root / entry.archive_path).read_bytes(), b"official-raw-bytes")
            with self.assertRaises(RawDocumentArchiveError):
                self._archive(root)

    def test_path_traversal_and_duplicate_source_ids_fail_closed(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            for unsafe in ("../escape", "a/b", ".."):
                with self.subTest(source_id=unsafe):
                    with self.assertRaises(RawDocumentArchiveError):
                        self._archive(root, source_id=unsafe)
            with self.assertRaises(RawDocumentArchiveError):
                self._archive(root, existing_source_ids=["omada-guide-v6"])

    def test_invalid_url_timestamp_or_empty_bytes_are_rejected(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            with self.assertRaises(RawDocumentArchiveError):
                self._archive(root, source_url="file:///tmp/guide.pdf")
            with self.assertRaises(RawDocumentArchiveError):
                self._archive(root, retrieved_at="not-a-time")
            with self.assertRaises(RawDocumentArchiveError):
                self._archive(root, raw_bytes=b"")


if __name__ == "__main__":
    unittest.main()
