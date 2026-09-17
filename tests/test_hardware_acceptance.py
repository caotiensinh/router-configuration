import unittest

from router_configuration.hardware_acceptance import (
    HardwareAcceptanceStatus,
    classify_hardware_plan,
    summarize_validation_scope,
)
from router_configuration.test_harness import (
    BackendKind,
    CommonScenario,
    EvidenceFidelity,
    ScenarioDisposition,
    ScenarioResult,
    TestBackendSpec,
    evaluate_vendor_test_results,
    plan_vendor_tests,
)


SOFTWARE_CAPABILITIES = {
    "discovery",
    "render_validate",
    "config_roundtrip",
    "config_backup",
    "config_restore",
    "management_probe",
    "multiwan",
    "routing",
    "dns",
    "vpn",
}


class HardwareAcceptancePolicyTests(unittest.TestCase):
    def _virtual_omada_backend(self):
        return TestBackendSpec.build(
            backend_id="omada-virtual-lab-01",
            vendor="omada",
            kind=BackendKind.VIRTUAL_APPLIANCE,
            fidelity=EvidenceFidelity.VENDOR_OS,
            capabilities=SOFTWARE_CAPABILITIES,
            lab_disposable=True,
            fault_injection_allowed=True,
            snapshot_restore_available=True,
        )

    def test_no_hardware_is_external_deferral_not_failure(self):
        plan = plan_vendor_tests(self._virtual_omada_backend())
        hardware_items = [
            item for item in plan.scenarios if item.min_fidelity is EvidenceFidelity.PHYSICAL
        ]

        self.assertTrue(hardware_items)
        self.assertTrue(
            all(item.disposition is ScenarioDisposition.DEFERRED for item in hardware_items)
        )
        self.assertEqual(
            classify_hardware_plan(plan),
            HardwareAcceptanceStatus.DEFERRED_EXTERNAL_HARDWARE,
        )

        summary = summarize_validation_scope(plan).as_dict()
        self.assertEqual(
            summary["hardware_acceptance_status"],
            "deferred_external_hardware",
        )
        self.assertFalse(summary["hardware_blocks_software_completion"])
        self.assertFalse(summary["hardware_certified"])
        self.assertFalse(summary["physical_certification_claimed"])

    def test_software_acceptance_can_pass_while_hardware_remains_deferred(self):
        plan = plan_vendor_tests(self._virtual_omada_backend())
        results = [
            ScenarioResult.build(
                scenario=item.scenario,
                passed=True,
                evidence_ref=f"software-{item.scenario.value}",
                fidelity=item.min_fidelity,
            )
            for item in plan.scenarios
            if item.disposition is ScenarioDisposition.RUN
        ]
        assessment = evaluate_vendor_test_results(plan, results)
        summary = summarize_validation_scope(plan, assessment).as_dict()

        self.assertTrue(summary["software_acceptance_passed"])
        self.assertEqual(
            summary["hardware_acceptance_status"],
            "deferred_external_hardware",
        )
        self.assertFalse(summary["hardware_blocks_software_completion"])
        self.assertFalse(summary["hardware_certified"])
        self.assertFalse(summary["physical_certification_claimed"])

    def test_physical_hardware_must_pass_before_physical_claim(self):
        backend = TestBackendSpec.build(
            backend_id="omada-physical-lab-01",
            vendor="omada",
            kind=BackendKind.PHYSICAL_DEVICE,
            fidelity=EvidenceFidelity.PHYSICAL,
            capabilities={"hardware_dataplane", "performance"},
            hardware_present=True,
            lab_disposable=True,
        )
        plan = plan_vendor_tests(
            backend,
            [CommonScenario.HARDWARE_DATAPLANE, CommonScenario.PERFORMANCE_CAPACITY],
        )

        self.assertEqual(
            classify_hardware_plan(plan),
            HardwareAcceptanceStatus.READY,
        )

        results = [
            ScenarioResult.build(
                scenario=item.scenario,
                passed=True,
                evidence_ref=f"physical-{item.scenario.value}",
                fidelity=EvidenceFidelity.PHYSICAL,
            )
            for item in plan.scenarios
        ]
        assessment = evaluate_vendor_test_results(plan, results)
        summary = summarize_validation_scope(plan, assessment).as_dict()

        self.assertEqual(summary["hardware_acceptance_status"], "verified")
        self.assertTrue(summary["hardware_certified"])
        self.assertTrue(summary["physical_certification_claimed"])

    def test_no_hardware_scenario_requested_is_not_requested(self):
        plan = plan_vendor_tests(
            self._virtual_omada_backend(),
            [CommonScenario.READ_ONLY_DISCOVERY, CommonScenario.RENDER_VALIDATE],
        )
        self.assertEqual(
            classify_hardware_plan(plan),
            HardwareAcceptanceStatus.NOT_REQUESTED,
        )


if __name__ == "__main__":
    unittest.main()
