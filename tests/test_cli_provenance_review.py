from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from router_configuration.cli import main


def _clean_summary() -> dict:
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


class ProvenanceReviewDraftCLITests(unittest.TestCase):
    def test_cli_writes_non_attested_bound_review_draft(self):
        with tempfile.TemporaryDirectory() as tmp:
            source = Path(tmp) / "clean-summary.json"
            output = Path(tmp) / "review-draft.json"
            source.write_text(json.dumps(_clean_summary()), encoding="utf-8")

            with patch("builtins.print") as printer:
                rc = main(
                    [
                        "provenance-review-draft",
                        "--summary",
                        str(source),
                        "--output",
                        str(output),
                    ]
                )

            self.assertEqual(rc, 0)
            draft = json.loads(output.read_text(encoding="utf-8"))
            self.assertEqual(draft["target_id"], "chr-live-v7")
            self.assertFalse(draft["operator_attested"])
            self.assertFalse(draft["candidate_review_complete"])
            self.assertFalse(draft["automatic_target_matrix_admission"])
            self.assertFalse(draft["write_authorized"])
            summary = json.loads(printer.call_args.args[0])
            self.assertFalse(summary["operator_attested"])
            self.assertEqual(summary["next_action"], "operator_review_and_attestation_required")

    def test_cli_rejects_machine_summary_that_claims_operator_attestation(self):
        payload = _clean_summary()
        payload["provenance"]["operator_attested"] = True
        with tempfile.TemporaryDirectory() as tmp:
            source = Path(tmp) / "bad-summary.json"
            output = Path(tmp) / "review-draft.json"
            source.write_text(json.dumps(payload), encoding="utf-8")
            with patch("builtins.print"):
                rc = main(
                    [
                        "provenance-review-draft",
                        "--summary",
                        str(source),
                        "--output",
                        str(output),
                    ]
                )
            self.assertEqual(rc, 2)
            self.assertFalse(output.exists())

    def test_parser_exposes_no_self_attestation_flag(self):
        with self.assertRaises(SystemExit):
            main(
                [
                    "provenance-review-draft",
                    "--summary",
                    "summary.json",
                    "--output",
                    "draft.json",
                    "--attest",
                ]
            )


if __name__ == "__main__":
    unittest.main()
