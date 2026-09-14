import unittest

from router_configuration.test_harness import CommonScenario
from router_configuration.vendors.mikrotik.chr_test_bridge import (
    ChrScriptCompilerEvidenceExecutor,
    build_chr_script_compiler_test_bundle,
    validate_chr_script_compiler_acceptance,
)


HEX_A = "a" * 64
HEX_B = "b" * 64
HEX_C = "c" * 64
HEX_D = "d" * 64
HEX_E = "e" * 64


def accepted_payload():
    return {
        "schema_version": "mikrotik-script-compiler-chr-acceptance/1",
        "ok": True,
        "routeros_target_version": "7.24.1",
        "routeros_observed_version": "7.24.1",
        "routeros_base_version": "7.24.1",
        "command_count": 8,
        "ordering_source": "deterministic",
        "script_sha256": HEX_A,
        "semantic_attestation_sha256": HEX_B,
        "dry_run_evidence_sha256": HEX_C,
        "knowledge_sha256": HEX_D,
        "approval_sha256": HEX_E,
        "negative_control_rejected": True,
        "configuration_unchanged": True,
        "temporary_files_removed": True,
        "write_authorized": False,
    }


class ChrCommonHarnessBridgeTests(unittest.TestCase):
    def test_live_chr_acceptance_maps_to_vendor_neutral_render_validate(self):
        bundle = build_chr_script_compiler_test_bundle(
            accepted_payload(),
            evidence_ref="artifact-mikrotik-script-compiler-acceptance",
        )

        self.assertEqual(bundle["schema_version"], "mikrotik-chr-common-test-bridge/1")
        self.assertEqual(bundle["plan"]["backend"]["vendor"], "mikrotik")
        self.assertEqual(bundle["plan"]["backend"]["kind"], "virtual_appliance")
        self.assertEqual(bundle["plan"]["backend"]["fidelity"], "vendor_os")
        self.assertEqual(bundle["plan"]["runnable_scenarios"], ["render_validate"])
        self.assertTrue(bundle["assessment"]["software_acceptance_passed"])
        self.assertFalse(bundle["assessment"]["hardware_certified"])
        self.assertFalse(bundle["hardware_certification_claimed"])
        self.assertFalse(bundle["production_writer_available"])
        self.assertFalse(bundle["write_authorized"])

    def test_bridge_rejects_any_write_authorization_claim(self):
        payload = accepted_payload()
        payload["write_authorized"] = True
        with self.assertRaisesRegex(ValueError, "write_authorized=false"):
            validate_chr_script_compiler_acceptance(payload)

    def test_bridge_rejects_changed_configuration(self):
        payload = accepted_payload()
        payload["configuration_unchanged"] = False
        with self.assertRaisesRegex(ValueError, "changed configuration"):
            validate_chr_script_compiler_acceptance(payload)

    def test_bridge_rejects_invalid_acceptance_digest(self):
        payload = accepted_payload()
        payload["approval_sha256"] = "not-a-digest"
        with self.assertRaisesRegex(ValueError, "approval_sha256"):
            validate_chr_script_compiler_acceptance(payload)

    def test_executor_is_bound_to_render_validate_only(self):
        executor = ChrScriptCompilerEvidenceExecutor(
            backend_id="mikrotik-chr-script-compiler",
            acceptance=accepted_payload(),
            evidence_ref="artifact-mikrotik-script-compiler-acceptance",
        )
        with self.assertRaisesRegex(ValueError, "only satisfy render_validate"):
            executor.run_scenario(CommonScenario.WAN_FAILOVER)


if __name__ == "__main__":
    unittest.main()
