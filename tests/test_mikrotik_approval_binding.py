import unittest

from router_configuration.vendors.mikrotik.approval_binding import (
    MikroTikApprovalError,
    MikroTikDryRunEvidence,
    build_approval_binding,
    dry_run_evidence_from_chr,
    validate_approval_fingerprint,
)
from router_configuration.vendors.mikrotik.script_planner import MikroTikScriptArtifact
from router_configuration.vendors.mikrotik.semantic_validation import MikroTikSemanticAttestation


def _artifact(script_sha="a" * 64):
    return MikroTikScriptArtifact(
        file_name="change.rsc",
        script="# test\n/ip/address/print\n",
        script_sha256=script_sha,
        render_sha256="render-001",
        ordered_command_ids=("inventory.1",),
        dry_run_command='/import file-name="change.rsc" verbose=yes dry-run',
    )


def _semantic(artifact):
    return MikroTikSemanticAttestation(
        render_sha256=artifact.render_sha256,
        script_sha256=artifact.script_sha256,
        ordered_command_ids=artifact.ordered_command_ids,
        passed=True,
        findings=(),
    )


def _proven_dry_run(artifact, *, passed=True, errors=()):
    return MikroTikDryRunEvidence(
        script_sha256=artifact.script_sha256,
        routeros_version="7.24.1",
        passed=passed,
        errors=errors,
        negative_control_rejected=True,
        configuration_unchanged=True,
        temporary_files_removed=True,
    )


class MikroTikApprovalBindingTests(unittest.TestCase):
    def test_chr_dry_run_parser_requires_full_provenance(self):
        artifact = _artifact()
        result = {
            "ok": True,
            "platform": {"version": "7.24.1"},
            "generated_script": {"sha256": artifact.script_sha256, "dry_run_passed": True},
            "negative_control": {"dry_run_rejected": True},
            "configuration_before_sha256": "x",
            "configuration_after_sha256": "x",
            "configuration_changed": False,
            "temporary_files_removed": True,
        }
        evidence = dry_run_evidence_from_chr(result=result, script=artifact)
        self.assertTrue(evidence.passed)
        self.assertTrue(evidence.negative_control_rejected)
        self.assertTrue(evidence.configuration_unchanged)
        self.assertTrue(evidence.temporary_files_removed)

    def test_chr_dry_run_parser_rejects_different_script_hash(self):
        artifact = _artifact()
        result = {
            "ok": True,
            "platform": {"version": "7.24.1"},
            "generated_script": {"sha256": "c" * 64, "dry_run_passed": True},
            "negative_control": {"dry_run_rejected": True},
            "configuration_before_sha256": "x",
            "configuration_after_sha256": "x",
            "configuration_changed": False,
            "temporary_files_removed": True,
        }
        with self.assertRaises(MikroTikApprovalError):
            dry_run_evidence_from_chr(result=result, script=artifact)

    def test_approval_binds_script_state_knowledge_semantics_and_dry_run(self):
        artifact = _artifact()
        binding = build_approval_binding(
            change_id="CHG-20260914-001",
            routeros_version="7.24.1",
            pre_state_sha256="b" * 64,
            script=artifact,
            semantic_attestation=_semantic(artifact),
            dry_run=_proven_dry_run(artifact),
        )
        self.assertEqual(len(binding.approval_sha256), 64)
        self.assertEqual(len(binding.knowledge_sha256), 64)
        self.assertEqual(len(binding.semantic_attestation_sha256), 64)
        validate_approval_fingerprint(binding, binding.approval_sha256)

    def test_failed_semantic_attestation_cannot_be_approved(self):
        artifact = _artifact()
        semantic = MikroTikSemanticAttestation(
            artifact.render_sha256,
            artifact.script_sha256,
            artifact.ordered_command_ids,
            False,
            (),
        )
        with self.assertRaisesRegex(MikroTikApprovalError, "semantic conflict"):
            build_approval_binding(
                change_id="CHG-1",
                routeros_version="7.24.1",
                pre_state_sha256="b" * 64,
                script=artifact,
                semantic_attestation=semantic,
                dry_run=_proven_dry_run(artifact),
            )

    def test_dry_run_for_different_script_is_rejected(self):
        artifact = _artifact()
        dry_run = MikroTikDryRunEvidence(
            script_sha256="c" * 64,
            routeros_version="7.24.1",
            passed=True,
            negative_control_rejected=True,
            configuration_unchanged=True,
            temporary_files_removed=True,
        )
        with self.assertRaises(MikroTikApprovalError):
            build_approval_binding(
                change_id="CHG-1",
                routeros_version="7.24.1",
                pre_state_sha256="b" * 64,
                script=artifact,
                semantic_attestation=_semantic(artifact),
                dry_run=dry_run,
            )

    def test_failed_dry_run_cannot_be_approved(self):
        artifact = _artifact()
        with self.assertRaises(MikroTikApprovalError):
            build_approval_binding(
                change_id="CHG-1",
                routeros_version="7.24.1",
                pre_state_sha256="b" * 64,
                script=artifact,
                semantic_attestation=_semantic(artifact),
                dry_run=_proven_dry_run(artifact, passed=False, errors=("syntax error",)),
            )

    def test_unproven_negative_control_cannot_be_approved(self):
        artifact = _artifact()
        dry_run = MikroTikDryRunEvidence(
            script_sha256=artifact.script_sha256,
            routeros_version="7.24.1",
            passed=True,
            negative_control_rejected=False,
            configuration_unchanged=True,
            temporary_files_removed=True,
        )
        with self.assertRaisesRegex(MikroTikApprovalError, "negative control"):
            build_approval_binding(
                change_id="CHG-1",
                routeros_version="7.24.1",
                pre_state_sha256="b" * 64,
                script=artifact,
                semantic_attestation=_semantic(artifact),
                dry_run=dry_run,
            )

    def test_stale_approval_hash_is_rejected(self):
        artifact = _artifact()
        binding = build_approval_binding(
            change_id="CHG-1",
            routeros_version="7.24.1",
            pre_state_sha256="b" * 64,
            script=artifact,
            semantic_attestation=_semantic(artifact),
            dry_run=_proven_dry_run(artifact),
        )
        with self.assertRaises(MikroTikApprovalError):
            validate_approval_fingerprint(binding, "d" * 64)


if __name__ == "__main__":
    unittest.main()
