from __future__ import annotations

import copy
import unittest

from router_configuration.provenance_review_package import (
    ProvenanceReviewPackageError,
    prepare_chr_provenance_review_package,
)


def _evidence() -> dict:
    return {
        "schema_version": "routeros-clean-readonly-summary/1",
        "target": "chr-live-v7",
        "routeros_version": "7.24.1 (stable)",
        "workflow_sha": "004cf819dd4ff95988482a7d1b84c2dd6727e6b3",
        "workflow_run_id": 33586254728,
        "artifact_id": 9830230324,
        "artifact_digest": "sha256:cb3c876983674693cc6ae4ae6d1c521d0af58cbe072cce3d47f69052436d0915",
        "normalized_state_sha256": "4ac53a6b66e9bfeac1cc502db89242a23c3f13f487980476ddd66fe229203413",
        "technical_admission": {
            "ok": True,
            "claim": "ready_for_operator_attestation",
            "acceptance_collection_write_operations_performed": False,
            "mutation_requests_attempted": False,
            "production_writer_available": False,
            "renderer_enabled": False,
            "write_authorized": False,
        },
        "provenance": {
            "machine_observation_only": True,
            "operator_attested": False,
            "automatic_target_matrix_admission": False,
        },
    }


class ProvenanceReviewPackageTests(unittest.TestCase):
    def test_package_binds_machine_evidence_without_self_attesting(self):
        result = prepare_chr_provenance_review_package(
            clean_readonly_summary=_evidence()
        ).as_dict()

        self.assertEqual(result["target_id"], "chr-live-v7")
        self.assertEqual(result["routeros_version"], "7.24.1 (stable)")
        self.assertEqual(
            result["normalized_state_sha256"], _evidence()["normalized_state_sha256"]
        )
        self.assertEqual(result["source_evidence"]["artifact_id"], 9830230324)
        self.assertFalse(result["operator_attested"])
        self.assertFalse(result["controlled_environment"])
        self.assertFalse(result["candidate_review_complete"])
        self.assertFalse(result["automatic_target_matrix_admission"])
        self.assertFalse(result["write_authorized"])

    def test_package_rejects_machine_evidence_that_claims_attestation(self):
        evidence = _evidence()
        evidence["provenance"]["operator_attested"] = True
        with self.assertRaisesRegex(ProvenanceReviewPackageError, "must not already claim"):
            prepare_chr_provenance_review_package(clean_readonly_summary=evidence)

    def test_package_rejects_any_write_or_writer_signal(self):
        for field in (
            "acceptance_collection_write_operations_performed",
            "mutation_requests_attempted",
            "production_writer_available",
            "renderer_enabled",
            "write_authorized",
        ):
            with self.subTest(field=field):
                evidence = copy.deepcopy(_evidence())
                evidence["technical_admission"][field] = True
                with self.assertRaisesRegex(ProvenanceReviewPackageError, field):
                    prepare_chr_provenance_review_package(clean_readonly_summary=evidence)

    def test_package_rejects_tampered_digest_shape(self):
        evidence = _evidence()
        evidence["normalized_state_sha256"] = "not-a-digest"
        with self.assertRaisesRegex(ProvenanceReviewPackageError, "lowercase SHA-256"):
            prepare_chr_provenance_review_package(clean_readonly_summary=evidence)


if __name__ == "__main__":
    unittest.main()
