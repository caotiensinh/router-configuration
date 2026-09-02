import unittest

from router_configuration.acceptance_bundle import AcceptanceBundleResult
from router_configuration.provenance import validate_provenance_attestation


VALID_STATE_SHA = "a" * 64


def valid_bundle() -> AcceptanceBundleResult:
    return AcceptanceBundleResult(
        errors=(),
        warnings=(),
        platform={"version": "7.24.1 (stable)", "board_name": "CHR"},
        routeros_version="7.24.1 (stable)",
        normalized_state_sha256=VALID_STATE_SHA,
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
        "normalized_state_sha256": VALID_STATE_SHA,
        "note": "read-only CHR acceptance observation",
    }


class ProvenanceAdmissionTests(unittest.TestCase):
    def test_valid_chr_attestation_is_only_eligible_for_review(self):
        result = validate_provenance_attestation(
            bundle_result=valid_bundle(),
            attestation=chr_attestation(),
        )
        self.assertTrue(result.ok, result.errors)
        payload = result.as_dict()
        self.assertEqual(payload["claim"], "eligible_for_target_matrix_review")
        self.assertFalse(payload["automatic_provenance_verification"])

    def test_synthetic_origin_cannot_claim_chr_provenance(self):
        attestation = chr_attestation()
        attestation["evidence_origin"] = "synthetic_fixture"
        result = validate_provenance_attestation(
            bundle_result=valid_bundle(),
            attestation=attestation,
        )
        self.assertFalse(result.ok)
        self.assertTrue(any("evidence_origin" in error for error in result.errors))

    def test_attested_version_and_digest_must_match_bundle(self):
        attestation = chr_attestation()
        attestation["routeros_version"] = "7.23.0 (stable)"
        attestation["normalized_state_sha256"] = "b" * 64
        result = validate_provenance_attestation(
            bundle_result=valid_bundle(),
            attestation=attestation,
        )
        self.assertFalse(result.ok)
        joined = "\n".join(result.errors)
        self.assertIn("routeros_version", joined)
        self.assertIn("normalized_state_sha256", joined)

    def test_attestation_must_explicitly_be_read_only(self):
        attestation = chr_attestation()
        attestation["write_operations_performed"] = True
        result = validate_provenance_attestation(
            bundle_result=valid_bundle(),
            attestation=attestation,
        )
        self.assertFalse(result.ok)
        self.assertTrue(any("write_operations_performed" in error for error in result.errors))

    def test_physical_target_requires_model(self):
        attestation = chr_attestation()
        attestation.update(
            {
                "target_id": "ccr2116-physical",
                "target_kind": "physical_router",
                "evidence_origin": "physical_router",
            }
        )
        result = validate_provenance_attestation(
            bundle_result=valid_bundle(),
            attestation=attestation,
        )
        self.assertFalse(result.ok)
        self.assertIn("physical_router attestation requires model", result.errors)

    def test_invalid_bundle_never_enters_provenance_review(self):
        bundle = AcceptanceBundleResult(
            errors=("tampered evidence",),
            warnings=(),
            routeros_version="7.24.1 (stable)",
            normalized_state_sha256=VALID_STATE_SHA,
        )
        result = validate_provenance_attestation(
            bundle_result=bundle,
            attestation=chr_attestation(),
        )
        self.assertFalse(result.ok)
        self.assertTrue(any("candidate bundle" in error for error in result.errors))


if __name__ == "__main__":
    unittest.main()
