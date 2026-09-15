from __future__ import annotations

import copy
import json
import unittest
from pathlib import Path

from router_configuration.p07_review_gate import (
    audit_verified_read_only_state,
    plan_verified_read_only_promotion,
    validate_p07_candidate,
    validate_p07_operator_attestation,
)


ROOT = Path(__file__).resolve().parents[1]
CANDIDATE_PATH = ROOT / "evidence" / "chr" / "p07-readonly-candidate-review.json"
TEMPLATE_PATH = ROOT / "evidence" / "chr" / "p07-operator-attestation.template.json"
MATRIX_PATH = ROOT / "ROUTEROS_TARGET_MATRIX.json"


def load(path: Path) -> dict:
    return json.loads(path.read_text(encoding="utf-8"))


def approved_attestation(candidate: dict) -> dict:
    payload = candidate["challenge_payload"]
    clean = payload["machine_evidence"]["clean_readonly_admission"]
    return {
        "schema_version": "routeros-provenance-attestation/1",
        "candidate_review_challenge_sha256": candidate[
            "candidate_review_challenge_sha256"
        ],
        "challenge_payload_sha256": candidate["challenge_payload_sha256"],
        "target_id": payload["target_id"],
        "target_kind": payload["target_kind"],
        "evidence_origin": "live_chr",
        "operator_attested": True,
        "decision": "approve",
        "controlled_environment": True,
        "write_operations_performed": False,
        "review_mode": "preserved_evidence_review",
        "direct_live_observation_claimed": False,
        "observed_at": "2026-09-15T14:00:00+09:00",
        "routeros_version": payload["routeros_version"],
        "normalized_state_sha256": clean["normalized_state_sha256"],
        "write_authorized": False,
        "physical_router_claimed": False,
        "production_write_authorized": False,
        "note": (
            "Human operator reviewed the hash-bound preserved GitHub workflow "
            "and artifact evidence; no direct live CHR observation is claimed."
        ),
    }


class P07ReviewGateTests(unittest.TestCase):
    def setUp(self):
        self.candidate = load(CANDIDATE_PATH)
        self.matrix = load(MATRIX_PATH)
        self.bound_matrix_blob = self.candidate["challenge_payload"][
            "target_matrix_blob_sha"
        ]

    def test_candidate_payload_is_hash_bound_and_fail_closed(self):
        result = validate_p07_candidate(
            candidate=self.candidate,
            matrix=self.matrix,
            matrix_blob_sha=self.bound_matrix_blob,
            enforce_pending_matrix=False,
        )
        self.assertTrue(result["ok"], result)
        self.assertFalse(result["operator_attested"])
        self.assertFalse(result["write_authorized"])

    def test_tampered_machine_evidence_breaks_payload_binding(self):
        candidate = copy.deepcopy(self.candidate)
        candidate["challenge_payload"]["machine_evidence"][
            "clean_readonly_admission"
        ]["artifact_id"] += 1
        result = validate_p07_candidate(
            candidate=candidate,
            matrix=self.matrix,
            matrix_blob_sha=self.bound_matrix_blob,
            enforce_pending_matrix=False,
        )
        self.assertFalse(result["ok"])
        self.assertTrue(
            any("challenge_payload_sha256" in error for error in result["errors"])
        )

    def test_stale_pending_matrix_blob_is_rejected(self):
        matrix = copy.deepcopy(self.matrix)
        target = next(item for item in matrix["targets"] if item["id"] == "chr-live-v7")
        target["status"] = "technical_readonly_validated_pending_attestation"
        result = validate_p07_candidate(
            candidate=self.candidate,
            matrix=matrix,
            matrix_blob_sha="f" * 40,
            enforce_pending_matrix=True,
        )
        self.assertFalse(result["ok"])
        self.assertTrue(any("stale" in error for error in result["errors"]))

    def test_non_attested_template_cannot_promote(self):
        attestation = load(TEMPLATE_PATH)
        result = validate_p07_operator_attestation(
            candidate=self.candidate,
            attestation=attestation,
        )
        self.assertFalse(result["ok"])
        self.assertTrue(any("operator_attested" in error for error in result["errors"]))

    def test_approval_must_match_both_challenge_and_payload_hash(self):
        attestation = approved_attestation(self.candidate)
        attestation["challenge_payload_sha256"] = "f" * 64
        result = validate_p07_operator_attestation(
            candidate=self.candidate,
            attestation=attestation,
        )
        self.assertFalse(result["ok"])
        self.assertTrue(any("bound challenge payload" in error for error in result["errors"]))

    def test_read_only_promotion_plan_never_authorizes_writes(self):
        matrix = copy.deepcopy(self.matrix)
        target = next(item for item in matrix["targets"] if item["id"] == "chr-live-v7")
        target["status"] = "technical_readonly_validated_pending_attestation"
        before = copy.deepcopy(matrix)
        attestation = approved_attestation(self.candidate)

        result = plan_verified_read_only_promotion(
            candidate=self.candidate,
            attestation=attestation,
            matrix=matrix,
            matrix_blob_sha=self.bound_matrix_blob,
        )
        self.assertTrue(result["ok"], result)
        self.assertEqual(matrix, before)
        self.assertFalse(result["matrix_mutated"])
        self.assertFalse(result["write_authorized"])
        proposed = next(
            item
            for item in result["proposed_matrix"]["targets"]
            if item["id"] == "chr-live-v7"
        )
        self.assertEqual(proposed["status"], "verified_read_only")
        self.assertEqual(proposed["remaining_acceptance"], [])
        self.assertFalse(proposed["technical_acceptance"]["write_authorized"])
        self.assertFalse(proposed["operator_review"]["write_authorized"])
        self.assertFalse(proposed["operator_review"]["physical_router_claimed"])
        self.assertFalse(proposed["operator_review"]["production_write_authorized"])

    def test_final_verified_state_is_auditable_against_same_attestation(self):
        matrix = copy.deepcopy(self.matrix)
        target = next(item for item in matrix["targets"] if item["id"] == "chr-live-v7")
        target["status"] = "technical_readonly_validated_pending_attestation"
        attestation = approved_attestation(self.candidate)
        plan = plan_verified_read_only_promotion(
            candidate=self.candidate,
            attestation=attestation,
            matrix=matrix,
            matrix_blob_sha=self.bound_matrix_blob,
        )
        self.assertTrue(plan["ok"], plan)

        audit = audit_verified_read_only_state(
            candidate=self.candidate,
            attestation=attestation,
            matrix=plan["proposed_matrix"],
            matrix_blob_sha="0" * 40,
        )
        self.assertTrue(audit["ok"], audit)
        self.assertEqual(audit["stage"], "verified_read_only_state_audited")
        self.assertFalse(audit["write_authorized"])

    def test_attestation_cannot_smuggle_write_or_physical_authorization(self):
        for field in (
            "write_authorized",
            "physical_router_claimed",
            "production_write_authorized",
        ):
            with self.subTest(field=field):
                attestation = approved_attestation(self.candidate)
                attestation[field] = True
                result = validate_p07_operator_attestation(
                    candidate=self.candidate,
                    attestation=attestation,
                )
                self.assertFalse(result["ok"])
                self.assertTrue(any(field in error for error in result["errors"]))


if __name__ == "__main__":
    unittest.main()
