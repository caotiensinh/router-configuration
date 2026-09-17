import unittest

from router_configuration.vendors.cisco.simulation_evidence import (
    PHYSICAL_LIMITATION_REASON,
    SIMULATION_LIMITATION_DISCLOSURE,
    CiscoSimulationEvidenceError,
    build_simulation_evidence,
    simulation_scope_status,
    validate_simulation_evidence,
)


SOURCE_SHA = "1" * 40
SIMULATOR_SHA = "2" * 40
SCENARIO_DIGEST = "3" * 64
INPUT_DIGEST = "4" * 64
PRE_STATE_DIGEST = "5" * 64
POST_STATE_DIGEST = "6" * 64
SIMULATION_PROFILE = "iosxe-config-rollback-v1"
ENVIRONMENT_KIND = "qualified_simulation"


def fixture() -> dict:
    return build_simulation_evidence(
        source_sha=SOURCE_SHA,
        simulator_sha=SIMULATOR_SHA,
        simulation_profile=SIMULATION_PROFILE,
        scenario_digest=SCENARIO_DIGEST,
        input_digest=INPUT_DIGEST,
        pre_state_digest=PRE_STATE_DIGEST,
        post_state_digest=POST_STATE_DIGEST,
        environment_kind=ENVIRONMENT_KIND,
        tested_logic=[
            "candidate/running configuration logic",
            "commit and rollback logic",
            "fault injection and restored-state comparison",
        ],
        evidence_refs=["artifact:network-sandbox:logic-run-001"],
    )


class CiscoSimulationEvidenceTests(unittest.TestCase):
    def test_simulation_evidence_explicitly_records_physical_limitation(self) -> None:
        evidence = fixture()
        self.assertEqual(evidence["evidence_scope"], "simulation_logic_only")
        self.assertFalse(evidence["physical_validation_performed"])
        self.assertFalse(evidence["physical_device_verified"])
        self.assertEqual(
            evidence["physical_validation_blocked_reason"],
            PHYSICAL_LIMITATION_REASON,
        )
        self.assertIn(SIMULATION_LIMITATION_DISCLOSURE, evidence["limitations"])
        self.assertFalse(evidence["production_validation_performed"])
        self.assertFalse(evidence["production_write_authorized"])
        self.assertFalse(evidence["canonical_acceptance_promoted"])
        self.assertEqual(evidence["claimed_acceptance_gates"], [])

    def test_cross_repository_provenance_is_explicit_and_pinned(self) -> None:
        evidence = fixture()
        self.assertEqual(evidence["router_configuration_sha"], SOURCE_SHA)
        self.assertEqual(evidence["network_sandbox_sha"], SIMULATOR_SHA)
        self.assertEqual(evidence["simulation_profile"], SIMULATION_PROFILE)
        self.assertEqual(evidence["scenario_digest"], SCENARIO_DIGEST)
        self.assertEqual(evidence["input_digest"], INPUT_DIGEST)
        self.assertEqual(evidence["pre_state_digest"], PRE_STATE_DIGEST)
        self.assertEqual(evidence["post_state_digest"], POST_STATE_DIGEST)
        self.assertEqual(evidence["environment_kind"], ENVIRONMENT_KIND)

    def test_scope_status_says_logic_only_and_not_real_hardware(self) -> None:
        status = simulation_scope_status()
        self.assertTrue(status["logic_simulation_allowed"])
        self.assertFalse(status["physical_validation_performed"])
        self.assertFalse(status["physical_device_verified"])
        self.assertEqual(
            status["physical_validation_blocked_reason"],
            "physical_hardware_unavailable",
        )
        self.assertIn("Physical Cisco hardware validation was not performed", status["disclosure"])
        self.assertFalse(status["canonical_acceptance_promoted"])

    def test_simulation_cannot_claim_physical_device_verification(self) -> None:
        evidence = fixture()
        evidence["physical_device_verified"] = True
        with self.assertRaisesRegex(
            CiscoSimulationEvidenceError,
            "physical_device_verified=false",
        ):
            validate_simulation_evidence(evidence)

    def test_simulation_cannot_claim_production_authorization(self) -> None:
        evidence = fixture()
        evidence["production_write_authorized"] = True
        with self.assertRaisesRegex(
            CiscoSimulationEvidenceError,
            "production_write_authorized=false",
        ):
            validate_simulation_evidence(evidence)

    def test_simulation_cannot_promote_canonical_acceptance(self) -> None:
        evidence = fixture()
        evidence["canonical_acceptance_promoted"] = True
        with self.assertRaisesRegex(
            CiscoSimulationEvidenceError,
            "canonical_acceptance_promoted=false",
        ):
            validate_simulation_evidence(evidence)

    def test_simulation_cannot_satisfy_physical_or_production_gates(self) -> None:
        for gate in (
            "C11.physical_evidence",
            "C11.physical_repository_acceptance",
            "C12.verified_production_deployment",
            "C12.final_handover_acceptance",
        ):
            with self.subTest(gate=gate):
                evidence = fixture()
                evidence["claimed_acceptance_gates"] = [gate]
                with self.assertRaisesRegex(
                    CiscoSimulationEvidenceError,
                    "cannot satisfy physical/production gates",
                ):
                    validate_simulation_evidence(evidence)

    def test_simulation_cannot_claim_any_canonical_acceptance_gate(self) -> None:
        evidence = fixture()
        evidence["claimed_acceptance_gates"] = ["C10.live_rollback_acceptance"]
        with self.assertRaisesRegex(
            CiscoSimulationEvidenceError,
            "cannot promote canonical acceptance gates",
        ):
            validate_simulation_evidence(evidence)

    def test_missing_provenance_field_is_rejected(self) -> None:
        evidence = fixture()
        evidence.pop("simulation_profile")
        with self.assertRaisesRegex(
            CiscoSimulationEvidenceError,
            "simulation_profile must be non-empty",
        ):
            validate_simulation_evidence(evidence)

    def test_invalid_scenario_digest_is_rejected(self) -> None:
        evidence = fixture()
        evidence["scenario_digest"] = "not-a-sha256"
        with self.assertRaisesRegex(
            CiscoSimulationEvidenceError,
            "scenario_digest must be a 64-character",
        ):
            validate_simulation_evidence(evidence)

    def test_router_configuration_sha_must_match_legacy_source_binding(self) -> None:
        evidence = fixture()
        evidence["router_configuration_sha"] = "7" * 40
        with self.assertRaisesRegex(
            CiscoSimulationEvidenceError,
            "router_configuration_sha must match source_sha",
        ):
            validate_simulation_evidence(evidence)

    def test_network_sandbox_sha_must_match_simulator_binding(self) -> None:
        evidence = fixture()
        evidence["network_sandbox_sha"] = "8" * 40
        with self.assertRaisesRegex(
            CiscoSimulationEvidenceError,
            "network_sandbox_sha must match simulator.source_sha",
        ):
            validate_simulation_evidence(evidence)

    def test_physical_environment_kind_is_rejected(self) -> None:
        with self.assertRaisesRegex(
            CiscoSimulationEvidenceError,
            "environment_kind must identify a simulation/emulation environment",
        ):
            build_simulation_evidence(
                source_sha=SOURCE_SHA,
                simulator_sha=SIMULATOR_SHA,
                simulation_profile=SIMULATION_PROFILE,
                scenario_digest=SCENARIO_DIGEST,
                input_digest=INPUT_DIGEST,
                pre_state_digest=PRE_STATE_DIGEST,
                post_state_digest=POST_STATE_DIGEST,
                environment_kind="physical_hardware",
                tested_logic=["candidate/running configuration logic"],
                evidence_refs=["artifact:network-sandbox:logic-run-001"],
            )

    def test_missing_physical_limitation_disclosure_is_rejected(self) -> None:
        evidence = fixture()
        evidence["limitations"] = []
        with self.assertRaisesRegex(
            CiscoSimulationEvidenceError,
            "physical Cisco hardware was not tested",
        ):
            validate_simulation_evidence(evidence)

    def test_missing_physical_block_reason_is_rejected(self) -> None:
        evidence = fixture()
        evidence["physical_validation_blocked_reason"] = ""
        with self.assertRaisesRegex(
            CiscoSimulationEvidenceError,
            "physical-hardware limitation",
        ):
            validate_simulation_evidence(evidence)

    def test_tampered_simulation_evidence_digest_is_rejected(self) -> None:
        evidence = fixture()
        evidence["tested_logic"].append("tampered after evidence creation")
        with self.assertRaisesRegex(CiscoSimulationEvidenceError, "digest mismatch"):
            validate_simulation_evidence(evidence)


if __name__ == "__main__":
    unittest.main()
