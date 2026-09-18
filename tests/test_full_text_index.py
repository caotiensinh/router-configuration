import unittest

from router_configuration.full_text_index import FullTextIndex, FullTextIndexError


class FullTextIndexTests(unittest.TestCase):
    def make_index(self):
        index = FullTextIndex()
        index.add_document(
            document_id="doc-a",
            title="Omada Portal Authentication",
            body="Controller portal authentication uses verified source evidence.",
            source_sha256="a" * 64,
        )
        index.add_document(
            document_id="doc-b",
            title="Omada Gateway Security",
            body="Gateway IDS IPS threat management security evidence.",
            source_sha256="b" * 64,
        )
        return index

    def test_and_search_returns_only_documents_with_all_terms(self):
        rows = self.make_index().search("gateway security")
        self.assertEqual([row["document_id"] for row in rows], ["doc-b"])

    def test_search_is_case_insensitive(self):
        rows = self.make_index().search("OMADA PORTAL")
        self.assertEqual([row["document_id"] for row in rows], ["doc-a"])

    def test_duplicate_document_id_is_rejected(self):
        index = self.make_index()
        with self.assertRaises(FullTextIndexError):
            index.add_document(
                document_id="doc-a",
                title="duplicate",
                body="duplicate",
                source_sha256="c" * 64,
            )

    def test_secret_metadata_is_rejected(self):
        index = FullTextIndex()
        with self.assertRaises(FullTextIndexError):
            index.add_document(
                document_id="doc-secret",
                title="secret",
                body="body",
                source_sha256="d" * 64,
                metadata={"client_secret": "forbidden"},
            )

    def test_manifest_digest_is_deterministic(self):
        a = self.make_index().manifest()
        b = self.make_index().manifest()
        self.assertEqual(a["index_sha256"], b["index_sha256"])


if __name__ == "__main__":
    unittest.main()
