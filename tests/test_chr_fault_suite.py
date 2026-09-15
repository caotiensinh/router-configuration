import copy
import json
import unittest
from pathlib import Path

from router_configuration.vendors.mikrotik.chr_fault_suite import (
    ChrFaultSuiteEntry,
    build_chr_fault_suite_test_bundle,
)


ROOT = Path(__file__).resolve().parents[1]
EVIDENCE = ROOT / "evidence" / "chr"


def load(name: str):
    return json.loads((EVIDENCE / name).read_text(encoding="utf-8"))


def accepted_entries():
    return (
        ChrFaultSuiteEntry(
            load("2026-09-14-dns-failure-7.24.1.json"),
            "committed-chr-dns-failure-7.24.1",
        ),
        ChrFaultSuiteEntry(
            load("2026-09-14-internet-down-link-up-7.24.1.json"),
            "committed-chr-internet-down-link-up-7.24.1",
        ),
        ChrFaultSuiteEntry(
            load("2026-09-14-route-loss-7.24.1.json"),
            "committed-chr-route-loss-7.24.1",
        ),
    )


class ChrFaultSuiteTests(unittest.TestCase):
    def test_three_independent_chr_runs_form_one_common_suite(self):
        bundle = build_chr_fault_suite_test_bundle(accepted_entries())

        self.assertEqual(bundle["schema_version"], "mikrotik-chr-fault-suite-common-test/1")
        self.assertEqual(bundle["routeros_base_version"], "7.24.1")
        self.assertEqual(bundle["scenario_count"], 3)
        self.assertEqual(
            set(bundle["plan"]["runnable_scenarios"]),
            {"wan_failover", "dns_failure", "default_route_loss"},
        )
        self.assertTrue(bundle["suite_scope_acceptance_passed"])
        self.assertTrue(bundle["assessment"]["software_acceptance_passed"])
        self.assertFalse(bundle["whole_vendor_software_certification_claimed"])
        self.assertFalse(bundle["hardware_certification_claimed"])
        self.assertFalse(bundle["assessment"]["hardware_certified"])
        self.assertFalse(bundle["production_writer_available"])
        self.assertFalse(bundle["write_authorized"])
        self.assertEqual(len(bundle["source_evidence"]), 3)
        self.assertTrue(all(len(row["source_evidence_sha256"]) == 64 for row in bundle["source_evidence"]))

    def test_duplicate_scenario_evidence_is_rejected(self):
        dns = load("2026-09-14-dns-failure-7.24.1.json")
        entries = (
            ChrFaultSuiteEntry(dns, "dns-one"),
            ChrFaultSuiteEntry(copy.deepcopy(dns), "dns-two"),
        )
        with self.assertRaisesRegex(ValueError, "duplicate CHR suite evidence"):
            build_chr_fault_suite_test_bundle(entries)

    def test_mixed_routeros_versions_are_rejected(self):
        entries = list(accepted_entries())
        changed = copy.deepcopy(entries[-1].payload)
        changed["routeros_version"] = "7.25.0"
        entries[-1] = ChrFaultSuiteEntry(changed, "route-loss-other-version")
        with self.assertRaisesRegex(ValueError, "one RouterOS base version"):
            build_chr_fault_suite_test_bundle(entries)

    def test_empty_suite_is_rejected(self):
        with self.assertRaisesRegex(ValueError, "at least one accepted CHR scenario"):
            build_chr_fault_suite_test_bundle(())


if __name__ == "__main__":
    unittest.main()
