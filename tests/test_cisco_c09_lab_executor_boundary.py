import unittest

from router_configuration.vendors.cisco.c08_acceptance_decision import bind_c08_repository_decision
from router_configuration.vendors.cisco.c08_human_approval_review import build_c08_human_approval_review_candidate
from router_configuration.vendors.cisco.c09_lab_executor_boundary import (
    CiscoC09LabExecutionBoundaryError,
    build_c09_lab_execution_boundary,
)
from router_configuration.vendors.cisco.validation_approval import CiscoApprovalBinding


SOURCE_SHA = "1" * 40
PRE_STATE = "a" * 64
PAYLOAD_DIGEST = "b" * 64
SCHEMA_DIGEST = "c" * 64
CATALOG_DIGEST = "d" * 64
VALIDATION_DIGEST = "e" * 64
APPROVAL_DIGEST = "f" * 64


def approval(
    *,
    model: str = "C8000V",
    version: str = "17.18.1a",
    train: str = "17.18",
    family: str = "Catalyst 8000V",
    role: str = "router",
) -> CiscoApprovalBinding:
    return CiscoApprovalBinding(
        change_id="CHG-C09-LAB-001",
        target_id="c8kv-lab-01",
        pre_state_sha256=PRE_STATE,
        payload_digest_sha256=PAYLOAD_DIGEST,
        schema_inventory_digest_sha256=SCHEMA_DIGEST,
        catalog_digest_sha256=CATALOG_DIGEST,
        validation_sha256=VALIDATION_DIGEST,
        model=model,
        iosxe_version=version,
        documentation_train=train,
        platform_family=family,
        role=role,
        feature_id="interface.description.set",
        target_datastore="candidate",
        approval_sha256=APPROVAL_DIGEST,
    )


def c08_decision(binding: CiscoApprovalBinding, *, decision: str = "accept") -> dict:
    evidence = {
        "schema_version": "cisco-c08-human-approval-evidence/1",
        "decision": "approved",
        "change_id": binding.change_id,
        "target_id": binding.target_id,
        "pre_state_sha256": binding.pre_state_sha256,
        "approval_sha256": binding.approval_sha256,
        "approver_ref": "human:lab-approver",
        "approval_record_id": "APR-C09-LAB-001",
        "approver_attestation_sha256": "8" * 64,
        "production_write_authorized": False,
    }
    review = build_c08_human_approval_review_candidate(evidence, binding=binding)
    return bind_c08_repository_decision(
        review,
        decision_id="DEC-C08-LAB-001",
        authority_ref="authority:repository-review",
        authority_attestation_sha256="9" * 64,
        decision=decision,
    )


def request(binding: CiscoApprovalBinding) -> dict:
    return {
        "schema_version": "cisco-c09-lab-execution-request/1",
        "request_id": "REQ-C09-LAB-001",
        "source_sha": SOURCE_SHA,
        "target_id": binding.target_id,
        "model": binding.model,
        "iosxe_version": binding.iosxe_version,
        "backend_kind": "virtual_appliance",
        "image_source_id": "CISCO-C8000V-INSTALL",
        "image_identity_sha256": "2" * 64,
        "operator_ref": "operator:c09-lab",
        "operator_attestation_sha256": "3" * 64,
        "requested_scenarios": [
            "read_only_discovery",
            "render_validate",
            "configuration_roundtrip",
            "management_survival",
        ],
        "lab_disposable": True,
        "lab_only": True,
        "operator_confirmed_lab_scope": True,
        "production_target": False,
        "hardware_present": False,
        "image_embedded_in_repository": False,
        "license_material_present": False,
        "production_writer_available": False,
        "production_write_authorized": False,
    }


class CiscoC09LabExecutorBoundaryTests(unittest.TestCase):
    def test_exact_accepted_c08_request_becomes_lab_execution_eligible(self) -> None:
        binding = approval()
        result = build_c09_lab_execution_boundary(
            request(binding),
            approval=binding,
            c08_decision=c08_decision(binding),
            source_sha=SOURCE_SHA,
        )
        self.assertTrue(result["eligible_for_controlled_lab_execution"])
        self.assertFalse(result["runtime_transport_present"])
        self.assertFalse(result["live_execution_observed"])
        self.assertFalse(result["c09_complete"])
        self.assertFalse(result["physical_hardware_claimed"])
        self.assertFalse(result["production_writer_available"])
        self.assertFalse(result["production_write_authorized"])
        self.assertEqual(result["approval_sha256"], binding.approval_sha256)
        self.assertEqual(result["source_sha"], SOURCE_SHA)
        self.assertEqual(len(result["boundary_record_sha256"]), 64)

    def test_rejected_or_tampered_c08_decision_fails_closed(self) -> None:
        binding = approval()
        with self.assertRaisesRegex(CiscoC09LabExecutionBoundaryError, "requires accepted C08"):
            build_c09_lab_execution_boundary(
                request(binding),
                approval=binding,
                c08_decision=c08_decision(binding, decision="reject"),
                source_sha=SOURCE_SHA,
            )

        tampered = c08_decision(binding)
        tampered["target_id"] = "different-target"
        with self.assertRaisesRegex(CiscoC09LabExecutionBoundaryError, "decision digest mismatch"):
            build_c09_lab_execution_boundary(
                request(binding),
                approval=binding,
                c08_decision=tampered,
                source_sha=SOURCE_SHA,
            )

    def test_source_target_model_and_version_are_exactly_bound(self) -> None:
        binding = approval()
        item = request(binding)
        item["source_sha"] = "4" * 40
        with self.assertRaisesRegex(CiscoC09LabExecutionBoundaryError, "source SHA differs"):
            build_c09_lab_execution_boundary(
                item,
                approval=binding,
                c08_decision=c08_decision(binding),
                source_sha=SOURCE_SHA,
            )

        item = request(binding)
        item["target_id"] = "c8kv-lab-02"
        with self.assertRaisesRegex(CiscoC09LabExecutionBoundaryError, "target differs"):
            build_c09_lab_execution_boundary(
                item,
                approval=binding,
                c08_decision=c08_decision(binding),
                source_sha=SOURCE_SHA,
            )

        item = request(binding)
        item["iosxe_version"] = "17.18.2"
        with self.assertRaisesRegex(CiscoC09LabExecutionBoundaryError, "model/version differs"):
            build_c09_lab_execution_boundary(
                item,
                approval=binding,
                c08_decision=c08_decision(binding),
                source_sha=SOURCE_SHA,
            )

    def test_only_admitted_catalyst_8000v_router_is_eligible(self) -> None:
        switch_binding = approval(model="C9300-24T", family="Catalyst 9300", role="switch")
        with self.assertRaisesRegex(CiscoC09LabExecutionBoundaryError, "bounded to Catalyst 8000V"):
            build_c09_lab_execution_boundary(
                request(switch_binding),
                approval=switch_binding,
                c08_decision=c08_decision(switch_binding),
                source_sha=SOURCE_SHA,
            )

        unknown_binding = approval(version="17.17.1", train="17.17")
        with self.assertRaisesRegex(CiscoC09LabExecutionBoundaryError, "not admitted"):
            build_c09_lab_execution_boundary(
                request(unknown_binding),
                approval=unknown_binding,
                c08_decision=c08_decision(unknown_binding),
                source_sha=SOURCE_SHA,
            )

    def test_production_hardware_embedded_image_and_license_claims_are_rejected(self) -> None:
        binding = approval()
        for field in (
            "production_target",
            "hardware_present",
            "image_embedded_in_repository",
            "license_material_present",
            "production_writer_available",
            "production_write_authorized",
        ):
            with self.subTest(field=field):
                item = request(binding)
                item[field] = True
                with self.assertRaisesRegex(CiscoC09LabExecutionBoundaryError, f"{field} must remain false"):
                    build_c09_lab_execution_boundary(
                        item,
                        approval=binding,
                        c08_decision=c08_decision(binding),
                        source_sha=SOURCE_SHA,
                    )

    def test_lab_scope_and_operator_attestation_are_mandatory(self) -> None:
        binding = approval()
        for field in ("lab_disposable", "lab_only", "operator_confirmed_lab_scope"):
            with self.subTest(field=field):
                item = request(binding)
                item[field] = False
                with self.assertRaisesRegex(CiscoC09LabExecutionBoundaryError, f"{field} must be true"):
                    build_c09_lab_execution_boundary(
                        item,
                        approval=binding,
                        c08_decision=c08_decision(binding),
                        source_sha=SOURCE_SHA,
                    )

        item = request(binding)
        item["operator_attestation_sha256"] = "bad"
        with self.assertRaisesRegex(CiscoC09LabExecutionBoundaryError, "operator_attestation_sha256"):
            build_c09_lab_execution_boundary(
                item,
                approval=binding,
                c08_decision=c08_decision(binding),
                source_sha=SOURCE_SHA,
            )

    def test_cisco_image_provenance_and_required_scenario_set_are_exact(self) -> None:
        binding = approval()
        item = request(binding)
        item["image_source_id"] = "unverified-source"
        with self.assertRaisesRegex(CiscoC09LabExecutionBoundaryError, "image provenance"):
            build_c09_lab_execution_boundary(
                item,
                approval=binding,
                c08_decision=c08_decision(binding),
                source_sha=SOURCE_SHA,
            )

        item = request(binding)
        item["requested_scenarios"] = item["requested_scenarios"][:-1]
        with self.assertRaisesRegex(CiscoC09LabExecutionBoundaryError, "exactly match"):
            build_c09_lab_execution_boundary(
                item,
                approval=binding,
                c08_decision=c08_decision(binding),
                source_sha=SOURCE_SHA,
            )

        item = request(binding)
        item["requested_scenarios"].append("read_only_discovery")
        with self.assertRaisesRegex(CiscoC09LabExecutionBoundaryError, "duplicates"):
            build_c09_lab_execution_boundary(
                item,
                approval=binding,
                c08_decision=c08_decision(binding),
                source_sha=SOURCE_SHA,
            )


if __name__ == "__main__":
    unittest.main()
