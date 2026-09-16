import json
import unittest
from dataclasses import replace

from router_configuration.test_harness import CommonScenario
from router_configuration.test_lab import StandardLabTopology
from router_configuration.vendors.cisco.desired_state import render_interface_description
from router_configuration.vendors.cisco.evidence_chain import (
    CiscoEvidenceChainError,
    build_structural_evidence_chain,
)
from router_configuration.vendors.cisco.transaction_execution_contract import build_recovery_execution_contract
from router_configuration.vendors.cisco.transaction_recovery import build_cisco_backup_evidence, build_cisco_recovery_plan
from router_configuration.vendors.cisco.validation_approval import build_approval_binding, validate_desired_state_render
from router_configuration.vendors.cisco.virtual_lab_evidence_ingest import ingest_cisco_virtual_lab_evidence_json

CANDIDATE = "urn:ietf:params:netconf:capability:candidate:1.0"
CONFIRMED = "urn:ietf:params:netconf:capability:confirmed-commit:1.1"
PRE_STATE = "a" * 64
SCHEMA = "b" * 64


def approval(change_id="CHG-CHAIN-001"):
    render = render_interface_description(
        model="C8000V",
        iosxe_version="17.18.1a",
        schema_inventory_digest_sha256=SCHEMA,
        observed_modules={"Cisco-IOS-XE-native"},
        netconf_capabilities={CANDIDATE},
        interface_name="1/0/1",
        description="chain-test",
    )
    validation = validate_desired_state_render(target_id="c8kv-lab-01", pre_state_sha256=PRE_STATE, render=render)
    return build_approval_binding(
        change_id=change_id,
        target_id="c8kv-lab-01",
        pre_state_sha256=PRE_STATE,
        render=render,
        validation=validation,
    )


def live_fixture(binding):
    def scenario(name, suffix):
        return {"scenario": name.value, "passed": True, "fidelity": "vendor_os", "evidence_ref": f"artifact:c09:{suffix}"}

    return {
        "schema_version": "cisco-iosxe-virtual-lab-evidence/1",
        "evidence_origin": "live_iosxe_virtual_appliance",
        "vendor": "Cisco",
        "os_family": "IOS XE",
        "backend_kind": "virtual_appliance",
        "backend_id": "cisco-c8kv-kvm-01",
        "target_id": binding.target_id,
        "model": binding.model,
        "iosxe_version": binding.iosxe_version,
        "source_sha": "1" * 40,
        "source_run_id": "34999999999",
        "artifact_digest_sha256": "2" * 64,
        "observed_identity_sha256": "3" * 64,
        "schema_inventory_digest_sha256": binding.schema_inventory_digest_sha256,
        "pre_state_sha256": binding.pre_state_sha256,
        "post_state_sha256": "4" * 64,
        "payload_digest_sha256": binding.payload_digest_sha256,
        "approval_sha256": binding.approval_sha256,
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


def artifacts(binding=None, *, c10_binding=None):
    binding = binding or approval()
    ingest = ingest_cisco_virtual_lab_evidence_json(json.dumps(live_fixture(binding), sort_keys=True), approval=binding)
    recovery_binding = c10_binding or binding
    backup = build_cisco_backup_evidence(
        target_id=recovery_binding.target_id,
        model=recovery_binding.model,
        iosxe_version=recovery_binding.iosxe_version,
        pre_state_sha256=recovery_binding.pre_state_sha256,
        snapshot_ref="artifact:cisco:c10:chain-prechange",
        snapshot_sha256="5" * 64,
    )
    plan = build_cisco_recovery_plan(
        approval=recovery_binding,
        backup=backup,
        c09_bundle_sha256=ingest["validated_bundle_sha256"],
        management_baseline_sha256="6" * 64,
        connectivity_baseline_sha256="7" * 64,
        observed_netconf_capabilities={CANDIDATE, CONFIRMED},
    )
    return binding, ingest, build_recovery_execution_contract(plan)


class CiscoEvidenceChainTests(unittest.TestCase):
    def test_chain_is_deterministic_and_never_promotes_acceptance(self):
        binding, ingest, contract = artifacts()
        first = build_structural_evidence_chain(approval=binding, c09_ingest=ingest, c10_contract=contract)
        second = build_structural_evidence_chain(approval=binding, c09_ingest=ingest, c10_contract=contract)
        self.assertEqual(first, second)
        self.assertTrue(first.chain_structurally_valid)
        self.assertFalse(first.raw_c09_bundle_replayed)
        self.assertFalse(first.repository_live_evidence_accepted)
        self.assertFalse(first.c09_complete)
        self.assertFalse(first.c10_complete)
        self.assertFalse(first.physical_device_verified)
        self.assertFalse(first.production_writer_available)
        self.assertFalse(first.production_write_authorized)
        self.assertEqual(len(first.chain_sha256), 64)

    def test_chain_binds_exact_c08_c09_and_c10_digests(self):
        binding, ingest, contract = artifacts()
        chain = build_structural_evidence_chain(approval=binding, c09_ingest=ingest, c10_contract=contract)
        self.assertEqual(chain.c08_approval_sha256, binding.approval_sha256)
        self.assertEqual(chain.c09_ingest_record_sha256, ingest["ingest_record_sha256"])
        self.assertEqual(chain.c09_validated_bundle_sha256, ingest["validated_bundle_sha256"])
        self.assertEqual(chain.c10_recovery_plan_sha256, contract.recovery_plan_sha256)
        self.assertEqual(chain.c10_execution_contract_sha256, contract.contract_sha256)

    def test_tampered_c08_digest_is_rejected(self):
        binding, ingest, contract = artifacts()
        with self.assertRaisesRegex(CiscoEvidenceChainError, "C08 approval binding digest mismatch"):
            build_structural_evidence_chain(approval=replace(binding, approval_sha256="9" * 64), c09_ingest=ingest, c10_contract=contract)

    def test_tampered_c09_ingest_record_is_rejected(self):
        binding, ingest, contract = artifacts()
        broken = dict(ingest)
        broken["source_run_id"] = "tampered"
        with self.assertRaisesRegex(CiscoEvidenceChainError, "C09 ingest record digest mismatch"):
            build_structural_evidence_chain(approval=binding, c09_ingest=broken, c10_contract=contract)

    def test_tampered_c10_contract_is_rejected(self):
        binding, ingest, contract = artifacts()
        broken = replace(contract, contract_sha256="8" * 64)
        with self.assertRaisesRegex(CiscoEvidenceChainError, "C10 execution contract digest mismatch"):
            build_structural_evidence_chain(approval=binding, c09_ingest=ingest, c10_contract=broken)

    def test_c10_must_bind_exact_c08_approval(self):
        binding = approval()
        alternate = approval(change_id="CHG-CHAIN-002")
        _, ingest, contract = artifacts(binding, c10_binding=alternate)
        with self.assertRaisesRegex(CiscoEvidenceChainError, "C10 approval digest"):
            build_structural_evidence_chain(approval=binding, c09_ingest=ingest, c10_contract=contract)

    def test_c10_must_bind_exact_c09_validated_bundle(self):
        binding, ingest, _ = artifacts()
        backup = build_cisco_backup_evidence(
            target_id=binding.target_id,
            model=binding.model,
            iosxe_version=binding.iosxe_version,
            pre_state_sha256=binding.pre_state_sha256,
            snapshot_ref="artifact:cisco:c10:other",
            snapshot_sha256="5" * 64,
        )
        plan = build_cisco_recovery_plan(
            approval=binding,
            backup=backup,
            c09_bundle_sha256="9" * 64,
            management_baseline_sha256="6" * 64,
            connectivity_baseline_sha256="7" * 64,
            observed_netconf_capabilities={CANDIDATE, CONFIRMED},
        )
        contract = build_recovery_execution_contract(plan)
        with self.assertRaisesRegex(CiscoEvidenceChainError, "does not bind the C09"):
            build_structural_evidence_chain(approval=binding, c09_ingest=ingest, c10_contract=contract)

    def test_c09_cannot_self_promote_repository_acceptance(self):
        binding, ingest, contract = artifacts()
        broken = dict(ingest)
        broken["repository_live_evidence_accepted"] = True
        unsigned = dict(broken)
        unsigned.pop("ingest_record_sha256")
        import hashlib
        broken["ingest_record_sha256"] = hashlib.sha256(json.dumps(unsigned, sort_keys=True, separators=(",", ":")).encode()).hexdigest()
        with self.assertRaisesRegex(CiscoEvidenceChainError, "cannot self-promote"):
            build_structural_evidence_chain(approval=binding, c09_ingest=broken, c10_contract=contract)


if __name__ == "__main__":
    unittest.main()
