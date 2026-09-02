import copy
import unittest

from router_configuration.provenance import ProvenanceAdmissionResult
from router_configuration.target_admission import plan_target_matrix_admission


BASE_MATRIX = {
    "schema_version": "1.0",
    "targets": [
        {
            "id": "synthetic-ci-fixture",
            "kind": "synthetic_fixture",
            "status": "verified_in_ci",
            "routeros_version": "7.24.1 (stable)",
        },
        {
            "id": "chr-live-v7",
            "kind": "routeros_chr",
            "status": "pending_live_read_only_evidence",
            "routeros_version": None,
        },
        {
            "id": "ccr2116-physical",
            "kind": "physical_router",
            "status": "pending_after_chr_acceptance",
            "routeros_version": None,
        },
    ],
}


def admission(target_id="chr-live-v7", target_kind="routeros_chr"):
    return ProvenanceAdmissionResult(
        errors=(),
        warnings=(),
        target_id=target_id,
        target_kind=target_kind,
        routeros_version="7.24.1 (stable)",
        normalized_state_sha256="a" * 64,
    )


def attestation(origin="live_chr"):
    return {
        "observed_at": "2026-09-02T10:45:00+09:00",
        "evidence_origin": origin,
        "controlled_environment": True,
        "write_operations_performed": False,
    }


class TargetAdmissionTests(unittest.TestCase):
    def test_chr_candidate_plan_does_not_mutate_matrix(self):
        matrix = copy.deepcopy(BASE_MATRIX)
        original = copy.deepcopy(matrix)
        result = plan_target_matrix_admission(
            matrix=matrix,
            provenance=admission(),
            attestation=attestation(),
        )
        self.assertTrue(result.ok, result.errors)
        self.assertEqual(matrix, original)
        payload = result.as_dict()
        self.assertFalse(payload["matrix_mutated"])
        self.assertTrue(payload["manual_acceptance_required"])
        self.assertEqual(
            payload["proposed_target"]["status"],
            "candidate_for_manual_acceptance",
        )

    def test_unknown_target_is_rejected(self):
        result = plan_target_matrix_admission(
            matrix=BASE_MATRIX,
            provenance=admission("unknown-target", "routeros_chr"),
            attestation=attestation(),
        )
        self.assertFalse(result.ok)
        self.assertTrue(any("not declared" in error for error in result.errors))

    def test_synthetic_target_cannot_receive_live_provenance(self):
        result = plan_target_matrix_admission(
            matrix=BASE_MATRIX,
            provenance=admission("synthetic-ci-fixture", "synthetic_fixture"),
            attestation=attestation("synthetic_fixture"),
        )
        self.assertFalse(result.ok)
        joined = "\n".join(result.errors)
        self.assertIn("synthetic fixture", joined)

    def test_physical_target_is_blocked_before_chr_acceptance(self):
        result = plan_target_matrix_admission(
            matrix=BASE_MATRIX,
            provenance=admission("ccr2116-physical", "physical_router"),
            attestation=attestation("physical_router"),
        )
        self.assertFalse(result.ok)
        self.assertTrue(any("chr-live-v7" in error for error in result.errors))

    def test_physical_target_can_be_candidate_after_chr_verified(self):
        matrix = copy.deepcopy(BASE_MATRIX)
        matrix["targets"][1]["status"] = "verified_read_only"
        result = plan_target_matrix_admission(
            matrix=matrix,
            provenance=admission("ccr2116-physical", "physical_router"),
            attestation=attestation("physical_router"),
        )
        self.assertTrue(result.ok, result.errors)
        self.assertEqual(
            result.as_dict()["proposed_target"]["status"],
            "candidate_for_manual_acceptance",
        )

    def test_existing_verified_target_gets_warning_and_not_overwritten(self):
        matrix = copy.deepcopy(BASE_MATRIX)
        matrix["targets"][1]["status"] = "verified_read_only"
        result = plan_target_matrix_admission(
            matrix=matrix,
            provenance=admission(),
            attestation=attestation(),
        )
        self.assertTrue(result.ok, result.errors)
        self.assertTrue(any("already has a verified status" in warning for warning in result.warnings))
        self.assertEqual(
            result.as_dict()["proposed_target"]["status"],
            "candidate_for_manual_acceptance",
        )


if __name__ == "__main__":
    unittest.main()
