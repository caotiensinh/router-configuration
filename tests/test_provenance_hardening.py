import unittest

from router_configuration.acceptance_bundle import AcceptanceBundleResult
from router_configuration.provenance import validate_provenance_attestation


STATE_SHA = "a" * 64


def bundle(board_name="CHR"):
    return AcceptanceBundleResult(
        errors=(),
        warnings=(),
        platform={"version": "7.24.1 (stable)", "board_name": board_name},
        routeros_version="7.24.1 (stable)",
        normalized_state_sha256=STATE_SHA,
    )


def chr_attestation():
    return {
        "schema_version": "routeros-provenance-attestation/1",
        "target_id": "chr-live-v7",
        "target_kind": "routeros_chr",
        "evidence_origin": "live_chr",
        "operator_attested": True,
        "controlled_environment": True,
        "write_operations_performed": False,
        "observed_at": "2026-09-02T10:45:00+09:00",
        "routeros_version": "7.24.1 (stable)",
        "normalized_state_sha256": STATE_SHA,
        "note": "read-only acceptance observation",
    }


class ProvenanceHardeningTests(unittest.TestCase):
    def test_target_id_injection_is_rejected(self):
        attestation = chr_attestation()
        attestation["target_id"] = "chr-live-v7;remove"
        result = validate_provenance_attestation(
            bundle_result=bundle(),
            attestation=attestation,
        )
        self.assertFalse(result.ok)
        self.assertTrue(any("target_id" in error for error in result.errors))

    def test_secret_like_attestation_field_is_rejected(self):
        attestation = chr_attestation()
        attestation["operator_token"] = "must-never-be-retained"
        result = validate_provenance_attestation(
            bundle_result=bundle(),
            attestation=attestation,
        )
        self.assertFalse(result.ok)
        self.assertTrue(any("secret-like" in error for error in result.errors))

    def test_nested_secret_like_attestation_field_is_rejected(self):
        attestation = chr_attestation()
        attestation["metadata"] = {"credential_ref": "should-not-be-in-provenance"}
        result = validate_provenance_attestation(
            bundle_result=bundle(),
            attestation=attestation,
        )
        self.assertFalse(result.ok)
        self.assertTrue(any("credential_ref" in error for error in result.errors))

    def test_physical_model_must_match_validated_platform(self):
        attestation = chr_attestation()
        attestation.update(
            {
                "target_id": "ccr2116-physical",
                "target_kind": "physical_router",
                "evidence_origin": "physical_router",
                "model": "CCR2116-12G-4S+",
            }
        )
        result = validate_provenance_attestation(
            bundle_result=bundle(board_name="CCR2004-16G-2S+"),
            attestation=attestation,
        )
        self.assertFalse(result.ok)
        self.assertTrue(any("model" in error for error in result.errors))

    def test_matching_physical_model_is_only_eligible_for_review(self):
        attestation = chr_attestation()
        attestation.update(
            {
                "target_id": "ccr2116-physical",
                "target_kind": "physical_router",
                "evidence_origin": "physical_router",
                "model": "CCR2116-12G-4S+",
            }
        )
        result = validate_provenance_attestation(
            bundle_result=bundle(board_name="CCR2116-12G-4S+"),
            attestation=attestation,
        )
        self.assertTrue(result.ok, result.errors)
        self.assertFalse(result.as_dict()["automatic_provenance_verification"])
        self.assertEqual(result.as_dict()["claim"], "eligible_for_target_matrix_review")


if __name__ == "__main__":
    unittest.main()
