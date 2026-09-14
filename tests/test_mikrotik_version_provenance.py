import unittest

from router_configuration.vendors.mikrotik.approval_binding import (
    MikroTikApprovalError,
    MikroTikDryRunEvidence,
    build_approval_binding,
    routeros_base_version,
)
from router_configuration.vendors.mikrotik.script_planner import MikroTikScriptArtifact
from router_configuration.vendors.mikrotik.semantic_validation import MikroTikSemanticAttestation


def _artifact():
    return MikroTikScriptArtifact(
        file_name="change.rsc",
        script="# test\n/ip/address/print\n",
        script_sha256="a" * 64,
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


def _dry_run(artifact, version):
    return MikroTikDryRunEvidence(
        script_sha256=artifact.script_sha256,
        routeros_version=version,
        passed=True,
        negative_control_rejected=True,
        configuration_unchanged=True,
        temporary_files_removed=True,
    )


class MikroTikVersionProvenanceTests(unittest.TestCase):
    def test_stable_channel_suffix_preserves_raw_but_matches_base_version(self):
        artifact = _artifact()
        dry_run = _dry_run(artifact, "7.24.1 (stable)")
        self.assertEqual(routeros_base_version(dry_run.routeros_version), "7.24.1")
        binding = build_approval_binding(
            change_id="CHG-1",
            routeros_version="7.24.1",
            pre_state_sha256="b" * 64,
            script=artifact,
            semantic_attestation=_semantic(artifact),
            dry_run=dry_run,
        )
        self.assertEqual(binding.routeros_version, "7.24.1")

    def test_real_base_version_mismatch_is_rejected(self):
        artifact = _artifact()
        with self.assertRaisesRegex(MikroTikApprovalError, "base version"):
            build_approval_binding(
                change_id="CHG-1",
                routeros_version="7.24.1",
                pre_state_sha256="b" * 64,
                script=artifact,
                semantic_attestation=_semantic(artifact),
                dry_run=_dry_run(artifact, "7.24.2 (stable)"),
            )

    def test_beta_version_token_is_preserved(self):
        self.assertEqual(routeros_base_version("7.25beta2 (testing)"), "7.25beta2")


if __name__ == "__main__":
    unittest.main()
