import hashlib
import json
import tempfile
import unittest
from pathlib import Path

from router_configuration.acceptance_bundle import validate_readonly_acceptance_bundle
from router_configuration.routeros_discovery import normalize_routeros_snapshot
from router_configuration.routeros_evidence import build_routeros_discovery_evidence


ROOT = Path(__file__).resolve().parents[1]
PROFILE_SOURCE = ROOT / "examples" / "rd-10g-1g" / "deployment-profile.json"
RAW_FIXTURE = ROOT / "tests" / "fixtures" / "routeros_readonly_snapshot.json"


def sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


class AcceptanceBundleTests(unittest.TestCase):
    def _bundle(self, directory: Path):
        profile = directory / "profile.json"
        evidence = directory / "evidence.json"
        manifest = directory / "manifest.json"

        profile.write_bytes(PROFILE_SOURCE.read_bytes())
        raw = json.loads(RAW_FIXTURE.read_text(encoding="utf-8"))
        evidence_payload = build_routeros_discovery_evidence(
            normalize_routeros_snapshot(raw)
        )
        evidence.write_text(
            json.dumps(evidence_payload, indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
        )
        manifest_payload = {
            "schema_version": "routeros-readonly-acceptance-manifest/1",
            "created_at": "2026-09-02T01:00:00Z",
            "claim_scope": "read_only_candidate_evidence",
            "profile_sha256": sha256(profile),
            "evidence_file_sha256": sha256(evidence),
            "normalized_state_sha256": evidence_payload["state_sha256"],
            "platform": evidence_payload["platform"],
            "note": "candidate only",
        }
        manifest.write_text(
            json.dumps(manifest_payload, indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
        )
        return profile, evidence, manifest

    def test_valid_bundle_is_ready_only_for_provenance_review(self):
        with tempfile.TemporaryDirectory() as tmp:
            profile, evidence, manifest = self._bundle(Path(tmp))
            result = validate_readonly_acceptance_bundle(
                profile_path=profile,
                evidence_path=evidence,
                manifest_path=manifest,
            )
            self.assertTrue(result.ok, result.errors)
            rendered = result.as_dict()
            self.assertEqual(rendered["claim"], "ready_for_provenance_review")
            self.assertFalse(rendered["provenance_verified"])
            self.assertEqual(rendered["routeros_version"], "7.24.1 (stable)")

    def test_tampered_evidence_file_breaks_manifest_and_state_integrity(self):
        with tempfile.TemporaryDirectory() as tmp:
            profile, evidence, manifest = self._bundle(Path(tmp))
            payload = json.loads(evidence.read_text(encoding="utf-8"))
            payload["normalized_state"]["interfaces"][0]["running"] = False
            evidence.write_text(json.dumps(payload), encoding="utf-8")
            result = validate_readonly_acceptance_bundle(
                profile_path=profile,
                evidence_path=evidence,
                manifest_path=manifest,
            )
            self.assertFalse(result.ok)
            joined = "\n".join(result.errors)
            self.assertIn("evidence_file_sha256", joined)
            self.assertIn("state_sha256", joined)

    def test_manifest_cannot_claim_verified_provenance(self):
        with tempfile.TemporaryDirectory() as tmp:
            profile, evidence, manifest = self._bundle(Path(tmp))
            payload = json.loads(manifest.read_text(encoding="utf-8"))
            payload["claim_scope"] = "verified_chr_evidence"
            manifest.write_text(json.dumps(payload), encoding="utf-8")
            result = validate_readonly_acceptance_bundle(
                profile_path=profile,
                evidence_path=evidence,
                manifest_path=manifest,
            )
            self.assertFalse(result.ok)
            self.assertTrue(any("claim_scope" in item for item in result.errors))

    def test_profile_hash_mismatch_is_rejected(self):
        with tempfile.TemporaryDirectory() as tmp:
            profile, evidence, manifest = self._bundle(Path(tmp))
            profile.write_text(profile.read_text(encoding="utf-8") + "\n", encoding="utf-8")
            result = validate_readonly_acceptance_bundle(
                profile_path=profile,
                evidence_path=evidence,
                manifest_path=manifest,
            )
            self.assertFalse(result.ok)
            self.assertIn(
                "manifest profile_sha256 does not match profile file",
                result.errors,
            )


if __name__ == "__main__":
    unittest.main()
