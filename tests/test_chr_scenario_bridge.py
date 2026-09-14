import copy
import json
import unittest
from pathlib import Path

from router_configuration.test_harness import CommonScenario
from router_configuration.vendors.mikrotik.chr_scenario_bridge import (
    build_chr_scenario_test_bundle,
    validate_chr_scenario_evidence,
)


ROOT = Path(__file__).resolve().parents[1]
EVIDENCE = ROOT / "evidence" / "chr"


def load(name: str):
    return json.loads((EVIDENCE / name).read_text(encoding="utf-8"))


class ChrScenarioBridgeTests(unittest.TestCase):
    def test_dns_failure_committed_evidence_maps_to_common_scenario(self):
        payload = load("2026-09-14-dns-failure-7.24.1.json")
        validated = validate_chr_scenario_evidence(payload)
        self.assertIs(validated.scenario, CommonScenario.DNS_FAILURE)

        bundle = build_chr_scenario_test_bundle(
            payload,
            evidence_ref="committed-chr-dns-failure-7.24.1",
        )
        self.assertEqual(bundle["scenario"], "dns_failure")
        self.assertEqual(bundle["plan"]["runnable_scenarios"], ["dns_failure"])
        self.assertTrue(bundle["scenario_scope_acceptance_passed"])
        self.assertFalse(bundle["whole_vendor_software_certification_claimed"])
        self.assertFalse(bundle["hardware_certification_claimed"])
        self.assertFalse(bundle["production_writer_available"])
        self.assertFalse(bundle["write_authorized"])
        self.assertEqual(
            bundle["source_provenance"]["workflow_run_id"],
            34810824257,
        )

    def test_link_up_blackhole_maps_to_wan_failover(self):
        payload = load("2026-09-14-internet-down-link-up-7.24.1.json")
        validated = validate_chr_scenario_evidence(payload)
        self.assertIs(validated.scenario, CommonScenario.WAN_FAILOVER)

        bundle = build_chr_scenario_test_bundle(
            payload,
            evidence_ref="committed-chr-internet-down-link-up-7.24.1",
        )
        self.assertEqual(bundle["scenario"], "wan_failover")
        self.assertTrue(bundle["scenario_scope_acceptance_passed"])
        self.assertEqual(bundle["plan"]["backend"]["fidelity"], "vendor_os")
        self.assertTrue(bundle["plan"]["backend"]["fault_injection_allowed"])
        self.assertFalse(bundle["assessment"]["hardware_certified"])

    def test_route_loss_maps_to_default_route_loss(self):
        payload = load("2026-09-14-route-loss-7.24.1.json")
        validated = validate_chr_scenario_evidence(payload)
        self.assertIs(validated.scenario, CommonScenario.DEFAULT_ROUTE_LOSS)

        bundle = build_chr_scenario_test_bundle(
            payload,
            evidence_ref="committed-chr-route-loss-7.24.1",
        )
        self.assertEqual(bundle["scenario"], "default_route_loss")
        self.assertTrue(bundle["scenario_scope_acceptance_passed"])
        self.assertEqual(
            bundle["source_provenance"]["artifact_digest"],
            "sha256:ff93f270d3bf6be09933ef1ed01e17b2a44e2bb96e88a8ebb4fd1d9f971f9fe6",
        )

    def test_dns_tamper_cannot_preserve_pass(self):
        payload = load("2026-09-14-dns-failure-7.24.1.json")
        tampered = copy.deepcopy(payload)
        tampered["semantics"]["dns_recovery_success"] = False
        with self.assertRaisesRegex(ValueError, "dns_recovery_success"):
            validate_chr_scenario_evidence(tampered)

    def test_failover_tamper_cannot_preserve_pass(self):
        payload = load("2026-09-14-internet-down-link-up-7.24.1.json")
        tampered = copy.deepcopy(payload)
        tampered["failure_injection"]["routeros_ether2_running"] = False
        with self.assertRaisesRegex(ValueError, "routeros_ether2_running"):
            validate_chr_scenario_evidence(tampered)

    def test_route_restore_tamper_cannot_preserve_pass(self):
        payload = load("2026-09-14-route-loss-7.24.1.json")
        tampered = copy.deepcopy(payload)
        tampered["semantics"]["same_route_ids_restored"] = False
        with self.assertRaisesRegex(ValueError, "same_route_ids_restored"):
            validate_chr_scenario_evidence(tampered)

    def test_physical_claim_in_dns_evidence_is_rejected(self):
        payload = load("2026-09-14-dns-failure-7.24.1.json")
        tampered = copy.deepcopy(payload)
        tampered["safety"]["physical_router_acceptance_claimed"] = True
        with self.assertRaisesRegex(ValueError, "physical_router_acceptance_claimed"):
            validate_chr_scenario_evidence(tampered)

    def test_unknown_schema_is_rejected(self):
        with self.assertRaisesRegex(ValueError, "unsupported CHR scenario evidence schema"):
            validate_chr_scenario_evidence({"schema_version": "unknown/1"})


if __name__ == "__main__":
    unittest.main()
