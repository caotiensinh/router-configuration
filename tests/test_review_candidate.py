import hashlib
import json
import tempfile
import unittest
from pathlib import Path

from router_configuration.review_candidate import review_candidate
from router_configuration.routeros_discovery import normalize_routeros_snapshot
from router_configuration.routeros_evidence import build_routeros_discovery_evidence


ROOT = Path(__file__).resolve().parents[1]
PROFILE_SOURCE = ROOT / "examples" / "rd-10g-1g" / "deployment-profile.json"
RAW_FIXTURE = ROOT / "tests" / "fixtures" / "routeros_readonly_snapshot.json"
MATRIX_SOURCE = ROOT / "ROUTEROS_TARGET_MATRIX.json"


def sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


class ReviewCandidateTests(unittest.TestCase):
    def _files(self, directory: Path):
        profile = directory / "profile.json"
        evidence = directory / "evidence.json"
        manifest = directory / "manifest.json"
        attestation = directory / "attestation.json"
        matrix = directory / "matrix.json"

        profile.write_bytes(PROFILE_SOURCE.read_bytes())
        raw = json.loads(RAW_FIXTURE.read_text(encoding="utf-8"))
        evidence_payload = build_routeros_discovery_evidence(
            normalize_routeros_snapshot(raw)
        )
        evidence.write_text(
            json.dumps(evidence_payload, indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
        )
        manifest.write_text(
            json.dumps(
                {
                    "schema_version": "routeros-readonly-acceptance-manifest/1",
                    "created_at": "2026-09-02T01:00:00Z",
                    "claim_scope": "read_only_candidate_evidence",
                    "profile_sha256": sha256(profile),
                    "evidence_file_sha256": sha256(evidence),
                    "normalized_state_sha256": evidence_payload["state_sha256"],
                    "platform": evidence_payload["platform"],
                },
                indent=2,
                sort_keys=True,
            )
            + "\n",
            encoding="utf-8",
        )
        attestation.write_text(
            json.dumps(
                {
                    "schema_version": "routeros-provenance-attestation/1",
                    "target_id": "chr-live-v7",
                    "target_kind": "routeros_chr",
                    "evidence_origin": "live_chr",
                    "operator_attested": True,
                    "controlled_environment": True,
                    "write_operations_performed": False,
                    "observed_at": "2026-09-02T10:45:00+09:00",
                    "routeros_version": evidence_payload["platform"]["version"],
                    "normalized_state_sha256": evidence_payload["state_sha256"],
                    "note": "synthetic test standing in only for orchestration coverage",
                },
                indent=2,
                sort_keys=True,
            )
            + "\n",
            encoding="utf-8",
        )
        matrix.write_bytes(MATRIX_SOURCE.read_bytes())
        return profile, evidence, manifest, attestation, matrix

    def test_valid_candidate_reaches_non_mutating_target_admission(self):
        with tempfile.TemporaryDirectory() as tmp:
            files = self._files(Path(tmp))
            payload = review_candidate(
                profile_path=files[0],
                evidence_path=files[1],
                manifest_path=files[2],
                attestation_path=files[3],
                matrix_path=files[4],
            )
            self.assertTrue(payload["ok"], payload)
            self.assertEqual(payload["stage"], "target_admission")
            self.assertFalse(payload["matrix_mutated"])
            self.assertEqual(
                payload["admission"]["proposed_target"]["status"],
                "candidate_for_manual_acceptance",
            )

    def test_tampered_evidence_stops_at_bundle_integrity(self):
        with tempfile.TemporaryDirectory() as tmp:
            profile, evidence, manifest, attestation, matrix = self._files(Path(tmp))
            payload = json.loads(evidence.read_text(encoding="utf-8"))
            payload["normalized_state"]["interfaces"][0]["running"] = False
            evidence.write_text(json.dumps(payload), encoding="utf-8")
            result = review_candidate(
                profile_path=profile,
                evidence_path=evidence,
                manifest_path=manifest,
                attestation_path=attestation,
                matrix_path=matrix,
            )
            self.assertFalse(result["ok"])
            self.assertEqual(result["stage"], "bundle_integrity")

    def test_bad_origin_stops_at_provenance(self):
        with tempfile.TemporaryDirectory() as tmp:
            profile, evidence, manifest, attestation, matrix = self._files(Path(tmp))
            payload = json.loads(attestation.read_text(encoding="utf-8"))
            payload["evidence_origin"] = "synthetic_fixture"
            attestation.write_text(json.dumps(payload), encoding="utf-8")
            result = review_candidate(
                profile_path=profile,
                evidence_path=evidence,
                manifest_path=manifest,
                attestation_path=attestation,
                matrix_path=matrix,
            )
            self.assertFalse(result["ok"])
            self.assertEqual(result["stage"], "provenance")

    def test_physical_target_stops_at_admission_until_chr_verified(self):
        with tempfile.TemporaryDirectory() as tmp:
            profile, evidence, manifest, attestation, matrix = self._files(Path(tmp))
            payload = json.loads(attestation.read_text(encoding="utf-8"))
            payload.update(
                {
                    "target_id": "ccr2116-physical",
                    "target_kind": "physical_router",
                    "evidence_origin": "physical_router",
                    "model": "CCR2116-12G-4S+",
                }
            )
            attestation.write_text(json.dumps(payload), encoding="utf-8")
            result = review_candidate(
                profile_path=profile,
                evidence_path=evidence,
                manifest_path=manifest,
                attestation_path=attestation,
                matrix_path=matrix,
            )
            self.assertFalse(result["ok"])
            self.assertEqual(result["stage"], "target_admission_blocked")
            self.assertTrue(
                any("chr-live-v7" in item for item in result["admission"]["errors"])
            )


if __name__ == "__main__":
    unittest.main()
