import copy
import unittest

from router_configuration.vendors.cisco.acceptance_evidence_ledger import (
    CiscoAcceptanceEvidenceLedgerError,
    build_acceptance_evidence_ledger,
)


def entries():
    result = {}
    for index, stage in enumerate(("c06", "c07", "c08", "c09", "c10", "c11", "c12"), start=1):
        result[stage] = {
            "status": "candidate",
            "artifact_sha256": f"{index:x}" * 64,
            "production_write_authorized": False,
        }
    return result


class CiscoAcceptanceEvidenceLedgerTests(unittest.TestCase):
    def test_ledger_is_deterministic_and_non_authorizing(self):
        first = build_acceptance_evidence_ledger(entries())
        second = build_acceptance_evidence_ledger(entries())
        self.assertEqual(first, second)
        self.assertEqual(first["accepted_prefix"], [])
        self.assertFalse(first["all_stages_accepted"])
        self.assertFalse(first["production_write_authorized"])
        self.assertEqual(len(first["ledger_sha256"]), 64)

    def test_accepted_prefix_is_ordered(self):
        item = entries()
        item["c06"]["status"] = "accepted"
        item["c07"]["status"] = "accepted"
        item["c08"]["status"] = "review_ready"
        result = build_acceptance_evidence_ledger(item)
        self.assertEqual(result["accepted_prefix"], ["c06", "c07"])
        self.assertEqual(result["accepted_stage_count"], 2)
        self.assertEqual(result["review_ready_stage_count"], 1)

    def test_missing_stage_or_write_authority_is_rejected(self):
        item = entries()
        del item["c12"]
        with self.assertRaisesRegex(CiscoAcceptanceEvidenceLedgerError, "exactly C06-C12"):
            build_acceptance_evidence_ledger(item)
        item = entries()
        item["c09"]["production_write_authorized"] = True
        with self.assertRaisesRegex(CiscoAcceptanceEvidenceLedgerError, "production write authority"):
            build_acceptance_evidence_ledger(item)


if __name__ == "__main__":
    unittest.main()
