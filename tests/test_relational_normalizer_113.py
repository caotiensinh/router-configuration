import unittest

from router_configuration.relational_normalizer import RelationalNormalizationError, normalize_relational_data


RAW = {
    "schema_version": "omada-raw-source-version/1",
    "source_id": "omada.portal.guide",
    "source_url": "https://support.omadanetworks.com/en/document/111643/",
    "retrieved_at": "2026-09-17T14:00:00Z",
    "archive_path": "archive/omada/portal-guide.html",
    "sha256": "b" * 64,
    "version_ordinal": 1,
    "state": "RAW_HASH_VERSION_BOUND",
}

FACT = {
    "fact_id": "fact.portal.controller-online",
    "subject_type": "portal-authentication",
    "subject_id": "omada-controller",
    "predicate": "controller_must_remain_online",
    "value": True,
    "source_id": "omada.portal.guide",
    "source_version_ordinal": 1,
    "evidence_locator": "Introduction/Conclusion",
    "confidence_class": "VENDOR_DOCUMENT_VERIFIED",
}


class RelationalNormalizerTests(unittest.TestCase):
    def test_normalizes_source_version_fact_and_provenance_tables(self):
        dataset = normalize_relational_data(raw_source_versions=[RAW], facts=[FACT]).as_dict()
        self.assertEqual(dataset["row_counts"]["sources"], 1)
        self.assertEqual(dataset["row_counts"]["source_versions"], 1)
        self.assertEqual(dataset["row_counts"]["facts"], 1)
        self.assertEqual(dataset["row_counts"]["fact_provenance"], 1)
        self.assertTrue(dataset["foreign_keys_validated"])
        self.assertEqual(len(dataset["dataset_sha256"]), 64)

    def test_output_is_deterministic_under_input_reordering(self):
        raw2 = dict(RAW, source_id="omada.portal.guide.2", source_url="https://support.omadanetworks.com/us/document/12927/", version_ordinal=1, sha256="c" * 64)
        fact2 = dict(FACT, fact_id="fact.portal.auth-types", source_id="omada.portal.guide.2", predicate="authentication_types", value=["HOTSPOT", "RADIUS"])
        a = normalize_relational_data(raw_source_versions=[RAW, raw2], facts=[FACT, fact2]).as_dict()
        b = normalize_relational_data(raw_source_versions=[raw2, RAW], facts=[fact2, FACT]).as_dict()
        self.assertEqual(a["dataset_sha256"], b["dataset_sha256"])

    def test_missing_provenance_foreign_key_fails_closed(self):
        broken = dict(FACT, source_version_ordinal=99)
        with self.assertRaises(RelationalNormalizationError):
            normalize_relational_data(raw_source_versions=[RAW], facts=[broken])

    def test_duplicate_fact_id_is_rejected(self):
        with self.assertRaises(RelationalNormalizationError):
            normalize_relational_data(raw_source_versions=[RAW], facts=[FACT, dict(FACT)])

    def test_secret_bearing_fields_are_rejected(self):
        secret_fact = dict(FACT, password="should-not-exist")
        with self.assertRaises(RelationalNormalizationError):
            normalize_relational_data(raw_source_versions=[RAW], facts=[secret_fact])


if __name__ == "__main__":
    unittest.main()
