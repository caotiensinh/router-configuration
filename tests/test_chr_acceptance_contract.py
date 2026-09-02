import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
RUNNER = ROOT / "lab" / "chr" / "run_readonly_acceptance.sh"


class ChrAcceptanceContractTests(unittest.TestCase):
    def test_runner_contains_only_read_only_routerctl_pipeline(self):
        source = RUNNER.read_text(encoding="utf-8")
        required = (
            "routerctl profile-check",
            "routerctl routeros-discover",
            "routerctl routeros-evidence-check",
            "routerctl routeros-preflight",
        )
        for command in required:
            self.assertIn(command, source)

        forbidden = (
            "routeros-apply",
            "routeros-render",
            "curl ",
            "wget ",
            " ssh ",
            "-X POST",
            "-X PUT",
            "-X PATCH",
            "-X DELETE",
        )
        for token in forbidden:
            self.assertNotIn(token, source)

    def test_runner_requires_secret_from_environment(self):
        source = RUNNER.read_text(encoding="utf-8")
        self.assertIn("ROUTEROS_PASSWORD", source)
        self.assertNotIn("--password ", source)
        self.assertIn("ROUTEROS_LAB_INSECURE_TLS", source)
        self.assertIn("--lab", source)
        self.assertIn("--no-verify-tls", source)

    def test_runner_manifest_does_not_claim_provenance(self):
        source = RUNNER.read_text(encoding="utf-8")
        self.assertIn('"claim_scope": "read_only_candidate_evidence"', source)
        self.assertIn("does not by itself prove CHR or physical-device provenance", source)


if __name__ == "__main__":
    unittest.main()
