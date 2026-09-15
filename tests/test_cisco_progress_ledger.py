import json
from pathlib import Path
import unittest

from router_configuration.vendors.cisco.progress_ledger import (
    CiscoProgressLedgerError,
    load_and_validate,
    validate_progress_ledger,
)

ROOT = Path(__file__).resolve().parents[1]
PATH = ROOT / "CISCO_PROGRESS.json"


def ledger():
    return json.loads(PATH.read_text(encoding="utf-8"))


class CiscoProgressLedgerTests(unittest.TestCase):
    def test_canonical_baseline(self):
        result = load_and_validate(PATH, repo_root=ROOT)
        self.assertEqual(result["completed"], 74)
        self.assertEqual(result["remaining"], 26)
        self.assertEqual(result["engineering"], {"earned": 74, "total": 79, "percent": 93.7})
        self.assertEqual(result["acceptance"], {"earned": 0, "total": 21, "percent": 0.0})

    def test_c05_existing_engineering_evidence_is_reconciled_without_acceptance(self):
        item = ledger()
        stage = next(s for s in item["stages"] if s["id"] == "C05")
        self.assertEqual(stage["earned"], 7)
        self.assertEqual(stage["status"], "in_progress")
        gates = {gate["id"]: gate for gate in stage["gates"]}
        self.assertEqual(gates["schema_mapping"]["status"], "pass")
        self.assertEqual(gates["normalizer_impl"]["status"], "pass")
        self.assertEqual(gates["tests_ci"]["status"], "pass")
        self.assertEqual(gates["evidence_pipeline"]["status"], "pending")
        self.assertEqual(gates["live_acceptance"]["status"], "blocked")
        self.assertEqual(gates["live_acceptance"]["earned"], 0)

    def test_top_level_tamper_is_rejected(self):
        item = ledger()
        item["completed_points"] = 75
        with self.assertRaisesRegex(CiscoProgressLedgerError, "completed_points mismatch"):
            validate_progress_ledger(item, repo_root=ROOT)

    def test_non_pass_gate_cannot_earn_points(self):
        item = ledger()
        gate = next(s for s in item["stages"] if s["id"] == "C03")["gates"][-1]
        gate["earned"] = gate["weight"]
        with self.assertRaisesRegex(CiscoProgressLedgerError, "earned must be 0"):
            validate_progress_ledger(item, repo_root=ROOT)

    def test_acceptance_gate_rejects_ci_only_pass(self):
        item = ledger()
        stage = next(s for s in item["stages"] if s["id"] == "C03")
        gate = stage["gates"][-1]
        gate["status"] = "pass"
        gate["earned"] = gate["weight"]
        gate["evidence"] = ["run:34990233893"]
        stage["earned"] += gate["weight"]
        stage["status"] = "done"
        item["completed_points"] += gate["weight"]
        item["remaining_points"] -= gate["weight"]
        item["overall_percent"] += gate["weight"]
        item["budgets"]["acceptance"]["earned"] += gate["weight"]
        item["budgets"]["acceptance"]["percent"] = round(
            item["budgets"]["acceptance"]["earned"] * 100 / item["budgets"]["acceptance"]["total"], 1
        )
        item["reconciliation"]["reconciled_points"] += gate["weight"]
        item["reconciliation"]["delta_points"] += gate["weight"]
        with self.assertRaisesRegex(CiscoProgressLedgerError, "acceptance PASS requires"):
            validate_progress_ledger(item, repo_root=ROOT)

    def test_missing_repository_evidence_is_rejected(self):
        item = ledger()
        item["stages"][0]["gates"][0]["evidence"] = ["path:not/a/real/file"]
        with self.assertRaisesRegex(CiscoProgressLedgerError, "missing repository evidence"):
            validate_progress_ledger(item, repo_root=ROOT)

    def test_pass_requires_evidence(self):
        item = ledger()
        item["stages"][0]["gates"][0]["evidence"] = []
        with self.assertRaisesRegex(CiscoProgressLedgerError, "PASS requires evidence"):
            validate_progress_ledger(item, repo_root=ROOT)


if __name__ == "__main__":
    unittest.main()
