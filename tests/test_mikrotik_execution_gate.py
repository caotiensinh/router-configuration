import unittest
from pathlib import Path

from router_configuration.governance import (
    GovernanceSnapshot,
    acknowledge,
    authorize,
)
from router_configuration.vendors.mikrotik.approval_binding import MikroTikApprovalBinding
from router_configuration.vendors.mikrotik.execution_gate import (
    MikroTikExecutionGateError,
    build_mikrotik_execution_gate_proof,
)


def _snapshot(*, include_mikrotik=True):
    vendor_rules = (
        (("vendors/mikrotik/VENDOR_RULES.md", "d" * 64),)
        if include_mikrotik
        else ()
    )
    return GovernanceSnapshot(
        root=Path("/tmp/router-configuration"),
        master_rules_sha256="a" * 64,
        agents_sha256="b" * 64,
        scoped_rule_sha256=(("governance/AI_POLICY.md", "c" * 64),),
        vendor_rule_sha256=vendor_rules,
    )


def _binding():
    return MikroTikApprovalBinding(
        change_id="CHG-001",
        routeros_version="7.24.1",
        pre_state_sha256="1" * 64,
        render_sha256="render-1",
        script_sha256="2" * 64,
        knowledge_sha256="3" * 64,
        semantic_attestation_sha256="4" * 64,
        dry_run_evidence_sha256="5" * 64,
        ordered_command_ids=("routing.10.default",),
        approval_sha256="6" * 64,
    )


class MikroTikExecutionGateTests(unittest.TestCase):
    def test_valid_governance_and_exact_approval_create_non_writer_proof(self):
        snapshot = _snapshot()
        governance = authorize(
            snapshot,
            acknowledge(snapshot),
            execution_policy_passed=True,
            approval_received=True,
        )
        proof = build_mikrotik_execution_gate_proof(
            binding=_binding(),
            approved_sha256="6" * 64,
            governance=governance,
        ).as_dict()
        self.assertTrue(proof["governance_authorized"])
        self.assertTrue(proof["changeset_approval_valid"])
        self.assertEqual(len(proof["governance_sha256"]), 64)
        self.assertEqual(len(proof["proof_sha256"]), 64)
        self.assertFalse(proof["production_writer_available"])
        self.assertFalse(proof["write_authorized"])
        self.assertFalse(proof["transport_present"])

    def test_execution_policy_or_human_approval_missing_is_rejected(self):
        snapshot = _snapshot()
        governance = authorize(
            snapshot,
            acknowledge(snapshot),
            execution_policy_passed=False,
            approval_received=True,
        )
        with self.assertRaisesRegex(MikroTikExecutionGateError, "execution policy PASS"):
            build_mikrotik_execution_gate_proof(
                binding=_binding(),
                approved_sha256="6" * 64,
                governance=governance,
            )

    def test_stale_changeset_approval_is_rejected(self):
        snapshot = _snapshot()
        governance = authorize(
            snapshot,
            acknowledge(snapshot),
            execution_policy_passed=True,
            approval_received=True,
        )
        with self.assertRaisesRegex(MikroTikExecutionGateError, "invalid or stale"):
            build_mikrotik_execution_gate_proof(
                binding=_binding(),
                approved_sha256="7" * 64,
                governance=governance,
            )

    def test_mikrotik_vendor_rules_are_mandatory(self):
        snapshot = _snapshot(include_mikrotik=False)
        governance = authorize(
            snapshot,
            acknowledge(snapshot),
            execution_policy_passed=True,
            approval_received=True,
        )
        with self.assertRaisesRegex(MikroTikExecutionGateError, "MikroTik vendor rules"):
            build_mikrotik_execution_gate_proof(
                binding=_binding(),
                approved_sha256="6" * 64,
                governance=governance,
            )


if __name__ == "__main__":
    unittest.main()
