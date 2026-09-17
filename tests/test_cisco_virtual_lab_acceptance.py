import unittest

from router_configuration.test_harness import CommonScenario
from router_configuration.test_lab import StandardLabTopology
from router_configuration.vendors.cisco.validation_approval import CiscoApprovalBinding
from router_configuration.vendors.cisco.virtual_lab_acceptance import (
    CiscoVirtualLabEvidenceError,
    build_cisco_virtual_lab_bundle,
    contract_only_status,
    validate_cisco_virtual_lab_evidence,
)


PRE_STATE = "a" * 64
PAYLOAD_DIGEST = "b" * 64
SCHEMA_DIGEST = "c" * 64
CATALOG_DIGEST = "d" * 64
VALIDATION_DIGEST = "e" * 64
APPROVAL_DIGEST = "f" * 64


def approval() -> CiscoApprovalBinding:
    return CiscoApprovalBinding(
        change_id="CHG-C09-001",
        target_id="c8kv-lab-01",
        pre_state_sha256=PRE_STATE,
        payload_digest_sha256=PAYLOAD_DIGEST,
        schema_inventory_digest_sha256=SCHEMA_DIGEST,
        catalog_digest_sha256=CATALOG_DIGEST,
        validation_sha256=VALIDATION_DIGEST,
        model="C8000V",
        iosxe_version="17.18.1a",
        documentation_train="17.18",
        platform_family="Catalyst 8000V",
        role="router",
        feature_id="interface.description.set",
        target_datastore="candidate",
        approval_sha256=APPROVAL_DIGEST,
    )


def scenario(name: CommonScenario, suffix: str) -> dict:
    return {
        "scenario": name.value,
        "passed": True,
        "fidelity": "vendor_os",
        "evidence_ref": f"artifact:c09:{suffix}",
    }


def live_fixture() -> dict:
    return {
        "schema_version": "cisco-iosxe-virtual-lab-evidence/1",
        "evidence_origin": "live_iosxe_virtual_appliance",
        "vendor": "Cisco",
        "os_family": "IOS XE",
        "backend_kind": "virtual_appliance",
        "backend_id": "cisco-c8kv-kvm-01",
        "target_id": "c8kv-lab-01",
        "model": "C8000V",
        "iosxe_version": "17.18.1a",
        "source_sha": "1" * 40,
        "source_run_id": "34999999999",
        "artifact_digest_sha256": "2" * 64,
        "observed_identity_sha256": "3" * 64,
        "schema_inventory_digest_sha256": SCHEMA_DIGEST,
        "pre_state_sha256": PRE_STATE,
        "post_state_sha256": "4" * 64,
        "payload_digest_sha256": PAYLOAD_DIGEST,
        "approval_sha256": APPROVAL_DIGEST,
        "topology_sha256": StandardLabTopology.build().as_dict()["topology_sha256"],
        "identity_observed": True,
        "lab_disposable": True,
        "fault_injection_lab_only": True,
        "lab_change_approved": True,
        "intended_state_verified": True,
        "management_survived_fault": True,
        "target_discarded_or_sanitized_after_run": True,
        "image_embedded_in_repository": False,
        "license_material_present": False,
        "hardware_present": False,
        "physical_hardware_claimed": False,
        "production_writer_available": False,
        "production_write_authorized": False,
        "scenarios": [
            scenario(CommonScenario.READ_ONLY_DISCOVERY, "read"),
            scenario(CommonScenario.RENDER_VALIDATE, "render"),
            scenario(CommonScenario.CONFIGURATION_ROUNDTRIP, "roundtrip"),
            scenario(CommonScenario.MANAGEMENT_SURVIVAL, "fault"),
        ],
    }


class CiscoVirtualLabAcceptanceTests(unittest.TestCase):
    def test_contract_only_status_cannot_close_c09(self) -> None:
        status = contract_only_status()
        self.assertFalse(status["synthetic_fixture_can_complete_c09"])
        self.assertFalse(status["live_virtual_iosxe_observed"])
        self.assertFalse(status["c09_complete"])
        self.assertFalse(status["physical_hardware_claimed"])
        self.assertFalse(status["production_writer_available"])
        self.assertFalse(status["production_write_authorized"])
        self.assertEqual(len(status["status_sha256"]), 64)

    def test_identified_live_c8000v_fixture_projects_to_common_harness(self) -> None:
        # This unit fixture tests the validator contract only. It is not accepted
        # repository evidence for C09; CI records contract_only_status() instead.
        bundle = build_cisco_virtual_lab_bundle(live_fixture(), approval=approval())
        self.assertTrue(bundle["live_virtual_iosxe_observed"])
        self.assertTrue(bundle["c09_complete"])
        self.assertFalse(bundle["physical_hardware_claimed"])
        self.assertFalse(bundle["production_writer_available"])
        self.assertFalse(bundle["production_write_authorized"])
        self.assertEqual(bundle["plan"]["deferred_scenarios"], [])
        self.assertEqual(len(bundle["bundle_sha256"]), 64)

    def test_non_live_or_wrong_backend_evidence_is_rejected(self) -> None:
        item = live_fixture()
        item["evidence_origin"] = "synthetic_fixture"
        with self.assertRaisesRegex(CiscoVirtualLabEvidenceError, "requires live"):
            validate_cisco_virtual_lab_evidence(item, approval=approval())
        item = live_fixture()
        item["backend_kind"] = "simulator"
        with self.assertRaisesRegex(CiscoVirtualLabEvidenceError, "virtual_appliance"):
            validate_cisco_virtual_lab_evidence(item, approval=approval())

    def test_initial_adapter_rejects_physical_switch_or_other_platform(self) -> None:
        item = live_fixture()
        item["model"] = "C9300-24T"
        with self.assertRaisesRegex(CiscoVirtualLabEvidenceError, "bounded to Catalyst 8000V"):
            validate_cisco_virtual_lab_evidence(item, approval=approval())

    def test_unknown_iosxe_train_is_rejected(self) -> None:
        item = live_fixture()
        item["iosxe_version"] = "17.17.1"
        with self.assertRaisesRegex(CiscoVirtualLabEvidenceError, "not admitted"):
            validate_cisco_virtual_lab_evidence(item, approval=approval())

    def test_target_model_version_and_schema_must_match_c08(self) -> None:
        item = live_fixture()
        item["target_id"] = "c8kv-lab-02"
        with self.assertRaisesRegex(CiscoVirtualLabEvidenceError, "target differs"):
            validate_cisco_virtual_lab_evidence(item, approval=approval())
        item = live_fixture()
        item["schema_inventory_digest_sha256"] = "9" * 64
        with self.assertRaisesRegex(CiscoVirtualLabEvidenceError, "schema inventory differs"):
            validate_cisco_virtual_lab_evidence(item, approval=approval())

    def test_pre_state_payload_and_approval_must_match_c08(self) -> None:
        fields = (
            ("pre_state_sha256", "pre-state differs"),
            ("payload_digest_sha256", "payload differs"),
            ("approval_sha256", "approval fingerprint differs"),
        )
        for field, message in fields:
            with self.subTest(field=field):
                item = live_fixture()
                item[field] = "9" * 64
                with self.assertRaisesRegex(CiscoVirtualLabEvidenceError, message):
                    validate_cisco_virtual_lab_evidence(item, approval=approval())

    def test_common_topology_binding_is_required(self) -> None:
        item = live_fixture()
        item["topology_sha256"] = "9" * 64
        with self.assertRaisesRegex(CiscoVirtualLabEvidenceError, "topology differs"):
            validate_cisco_virtual_lab_evidence(item, approval=approval())

    def test_every_required_scenario_must_pass_at_vendor_os_fidelity(self) -> None:
        item = live_fixture()
        item["scenarios"] = item["scenarios"][:-1]
        with self.assertRaisesRegex(CiscoVirtualLabEvidenceError, "missing required"):
            validate_cisco_virtual_lab_evidence(item, approval=approval())
        item = live_fixture()
        item["scenarios"][2]["fidelity"] = "behavior"
        with self.assertRaisesRegex(CiscoVirtualLabEvidenceError, "lacks vendor_os fidelity"):
            validate_cisco_virtual_lab_evidence(item, approval=approval())
        item = live_fixture()
        item["scenarios"][0]["passed"] = False
        with self.assertRaisesRegex(CiscoVirtualLabEvidenceError, "did not pass"):
            validate_cisco_virtual_lab_evidence(item, approval=approval())

    def test_duplicate_or_unexpected_scenarios_are_rejected(self) -> None:
        item = live_fixture()
        item["scenarios"].append(dict(item["scenarios"][0]))
        with self.assertRaisesRegex(CiscoVirtualLabEvidenceError, "duplicate"):
            validate_cisco_virtual_lab_evidence(item, approval=approval())
        item = live_fixture()
        item["scenarios"][0]["scenario"] = CommonScenario.DNS_FAILURE.value
        with self.assertRaisesRegex(CiscoVirtualLabEvidenceError, "unexpected C09 scenario"):
            validate_cisco_virtual_lab_evidence(item, approval=approval())

    def test_lab_safety_flags_fail_closed(self) -> None:
        for field in (
            "identity_observed",
            "lab_disposable",
            "fault_injection_lab_only",
            "lab_change_approved",
            "intended_state_verified",
            "management_survived_fault",
            "target_discarded_or_sanitized_after_run",
        ):
            with self.subTest(field=field):
                item = live_fixture()
                item[field] = False
                with self.assertRaisesRegex(CiscoVirtualLabEvidenceError, f"{field} must be true"):
                    validate_cisco_virtual_lab_evidence(item, approval=approval())

    def test_proprietary_image_license_hardware_and_production_claims_are_rejected(self) -> None:
        for field in (
            "image_embedded_in_repository",
            "license_material_present",
            "hardware_present",
            "physical_hardware_claimed",
            "production_writer_available",
            "production_write_authorized",
        ):
            with self.subTest(field=field):
                item = live_fixture()
                item[field] = True
                with self.assertRaisesRegex(CiscoVirtualLabEvidenceError, f"{field} must remain false"):
                    validate_cisco_virtual_lab_evidence(item, approval=approval())

    def test_source_provenance_and_refs_are_sanitized(self) -> None:
        item = live_fixture()
        item["source_sha"] = "bad"
        with self.assertRaisesRegex(CiscoVirtualLabEvidenceError, "Git SHA"):
            validate_cisco_virtual_lab_evidence(item, approval=approval())
        item = live_fixture()
        item["scenarios"][0]["evidence_ref"] = "https://host/?token=secret"
        with self.assertRaises(CiscoVirtualLabEvidenceError):
            validate_cisco_virtual_lab_evidence(item, approval=approval())


if __name__ == "__main__":
    unittest.main()
