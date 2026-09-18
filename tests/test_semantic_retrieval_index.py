import unittest

from router_configuration.semantic_retrieval_index import SemanticIndexError, SemanticRetrievalIndex


class SemanticRetrievalIndexTests(unittest.TestCase):
    def make_index(self):
        index = SemanticRetrievalIndex(embedding_model="fixture-embedding-model-v1", dimension=3)
        index.add_document(
            document_id="vpn",
            title="VPN knowledge",
            source_sha256="a" * 64,
            vector=[1.0, 0.0, 0.0],
            vector_provenance_ref="embedding://fixture/vpn",
        )
        index.add_document(
            document_id="portal",
            title="Portal authentication",
            source_sha256="b" * 64,
            vector=[0.0, 1.0, 0.0],
            vector_provenance_ref="embedding://fixture/portal",
        )
        return index

    def test_cosine_retrieval_is_deterministic(self):
        rows = self.make_index().search([0.9, 0.1, 0.0], limit=2)
        self.assertEqual(rows[0]["document_id"], "vpn")
        self.assertGreater(rows[0]["score"], rows[1]["score"])

    def test_dimension_mismatch_is_rejected(self):
        with self.assertRaises(SemanticIndexError):
            self.make_index().search([1.0, 0.0])

    def test_zero_norm_vector_is_rejected(self):
        index = SemanticRetrievalIndex(embedding_model="fixture", dimension=3)
        with self.assertRaises(SemanticIndexError):
            index.add_document(
                document_id="bad",
                title="bad",
                source_sha256="c" * 64,
                vector=[0.0, 0.0, 0.0],
                vector_provenance_ref="embedding://fixture/bad",
            )

    def test_duplicate_document_id_is_rejected(self):
        index = self.make_index()
        with self.assertRaises(SemanticIndexError):
            index.add_document(
                document_id="vpn",
                title="duplicate",
                source_sha256="d" * 64,
                vector=[1.0, 0.0, 0.0],
                vector_provenance_ref="embedding://fixture/dup",
            )

    def test_manifest_does_not_claim_embedding_generation(self):
        manifest = self.make_index().manifest()
        self.assertFalse(manifest["embedding_generation_in_scope"])
        self.assertEqual(len(manifest["index_sha256"]), 64)


if __name__ == "__main__":
    unittest.main()
