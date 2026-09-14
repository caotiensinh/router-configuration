import unittest

from router_configuration.test_harness import (
    BackendKind,
    CommonScenario,
    EvidenceFidelity,
    ScenarioDisposition,
    ScenarioResult,
    TestBackendSpec,
    canonical_vendor,
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


class VendorNeutralTestHarnessTests(unittest.TestCase):
    def _vendor_os_backend(self, vendor="mikrotik"):
        return TestBackendSpec.build(
            backend_id=f"{vendor}-lab-vm-01",
            vendor=vendor,
            kind=BackendKind.VIRTUAL_APPLIANCE,
            fidelity=EvidenceFidelity.VENDOR_OS,
            capabilities=SOFTWARE_CAPABILITIES,
            lab_disposable=True,
            fault_injection_allowed=True,
            snapshot_restore_available=True,
        )

    def test_vendor_aliases_are_normalized_without_limiting_future_vendors(self):
        self.assertEqual(canonical_vendor("RouterOS"), "mikrotik")
        self.assertEqual(canonical_vendor("IOS-XE"), "cisco")
        self.assertEqual(canonical_vendor("Omada"), "tp-link")
        self.assertEqual(canonical_vendor("FortiGate"), "fortinet")
        self.assertEqual(canonical_vendor("future-vendor"), "future-vendor")

    def test_vendor_os_vm_runs_software_scenarios_and_defers_hardware(self):
        plan = plan_vendor_tests(self._vendor_os_backend())
        by_name = {item.scenario: item for item in plan.scenarios}

        self.assertEqual(
            by_name[CommonScenario.WAN_FAILOVER].disposition,
            ScenarioDisposition.RUN,
        )
        self.assertEqual(
            by_name[CommonScenario.ROLLBACK_RECOVERY].disposition,
            ScenarioDisposition.RUN,
        )
        self.assertEqual(
            by_name[CommonScenario.HARDWARE_DATAPLANE].disposition,
            ScenarioDisposition.DEFERRED,
        )
        self.assertEqual(
            by_name[CommonScenario.PERFORMANCE_CAPACITY].disposition,
            ScenarioDisposition.DEFERRED,
        )
        self.assertTrue(plan.as_dict()["software_plan_fully_runnable"])
        self.assertFalse(plan.as_dict()["hardware_certification_possible"])
        self.assertFalse(plan.as_dict()["write_authorized"])

    def test_behavior_model_cannot_claim_vendor_os_acceptance(self):
        backend = TestBackendSpec.build(
            backend_id="cisco-contract-model-01",
            vendor="cisco",
            kind=BackendKind.BEHAVIOR_MODEL,
            fidelity=EvidenceFidelity.BEHAVIOR,
            capabilities={"discovery", "render_validate", "routing", "dns"},
            lab_disposable=True,
            fault_injection_allowed=True,
        )
        plan = plan_vendor_tests(backend)
        by_name = {item.scenario: item for item in plan.scenarios}

        self.assertEqual(
            by_name[CommonScenario.READ_ONLY_DISCOVERY].disposition,
            ScenarioDisposition.RUN,
        )
        self.assertEqual(
            by_name[CommonScenario.RENDER_VALIDATE].disposition,
            ScenarioDisposition.RUN,
        )
        self.assertEqual(
            by_name[CommonScenario.DEFAULT_ROUTE_LOSS].disposition,
            ScenarioDisposition.DEFERRED,
        )
        self.assertTrue(
            any("vendor_os fidelity" in reason for reason in by_name[CommonScenario.DEFAULT_ROUTE_LOSS].reasons)
        )

    def test_fault_injection_requires_disposable_lab(self):
        backend = TestBackendSpec.build(
            backend_id="yamaha-nondisposable-01",
            vendor="yamaha",
            kind=BackendKind.VIRTUAL_APPLIANCE,
            fidelity=EvidenceFidelity.VENDOR_OS,
            capabilities=SOFTWARE_CAPABILITIES,
            lab_disposable=False,
            fault_injection_allowed=True,
            snapshot_restore_available=True,
        )
        plan = plan_vendor_tests(backend, [CommonScenario.DNS_FAILURE])
        item = plan.scenarios[0]
        self.assertEqual(item.disposition, ScenarioDisposition.DEFERRED)
        self.assertIn("fault injection requires a declared lab/disposable target", item.reasons)

    def test_physical_backend_can_make_hardware_scenarios_runnable(self):
        backend = TestBackendSpec.build(
            backend_id="fortinet-physical-lab-01",
            vendor="fortigate",
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
        self.assertTrue(all(item.disposition is ScenarioDisposition.RUN for item in plan.scenarios))
        self.assertTrue(plan.as_dict()["hardware_certification_possible"])

    def test_test_backend_cannot_authorize_production_writes(self):
        with self.assertRaisesRegex(ValueError, "cannot authorize production writes"):
            TestBackendSpec.build(
                backend_id="unsafe-backend",
                vendor="mikrotik",
                kind=BackendKind.VIRTUAL_APPLIANCE,
                fidelity=EvidenceFidelity.VENDOR_OS,
                capabilities=SOFTWARE_CAPABILITIES,
                production_write_authorized=True,
            )

    def test_virtual_vendor_os_can_pass_software_acceptance_without_hardware_claim(self):
        plan = plan_vendor_tests(self._vendor_os_backend("tp-link"))
        results = []
        for item in plan.scenarios:
            if item.disposition is not ScenarioDisposition.RUN:
                continue
            results.append(
                ScenarioResult.build(
                    scenario=item.scenario,
                    passed=True,
                    evidence_ref=f"artifact-{item.scenario.value}",
                    fidelity=item.min_fidelity,
                )
            )

        assessment = evaluate_vendor_test_results(plan, results).as_dict()
        self.assertTrue(assessment["software_acceptance_passed"])
        self.assertFalse(assessment["hardware_certified"])
        self.assertIn("hardware_dataplane", assessment["deferred_scenarios"])
        self.assertFalse(assessment["production_writer_available"])
        self.assertFalse(assessment["write_authorized"])

    def test_result_cannot_claim_fidelity_above_backend(self):
        backend = TestBackendSpec.build(
            backend_id="sim-01",
            vendor="cisco",
            kind=BackendKind.SIMULATOR,
            fidelity=EvidenceFidelity.BEHAVIOR,
            capabilities={"discovery"},
        )
        plan = plan_vendor_tests(backend, [CommonScenario.READ_ONLY_DISCOVERY])
        result = ScenarioResult.build(
            scenario=CommonScenario.READ_ONLY_DISCOVERY,
            passed=True,
            evidence_ref="sim-evidence-01",
            fidelity=EvidenceFidelity.VENDOR_OS,
        )
        with self.assertRaisesRegex(ValueError, "exceeds backend fidelity"):
            evaluate_vendor_test_results(plan, [result])


if __name__ == "__main__":
    unittest.main()
