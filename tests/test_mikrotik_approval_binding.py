import unittest

from router_configuration.vendors.mikrotik.approval_binding import (
    MikroTikApprovalError,
    MikroTikDryRunEvidence,
    build_approval_binding,
    validate_approval_fingerprint,
)
from router_configuration.vendors.mikrotik.script_planner import MikroTikScriptArtifact


def _artifact(script_sha="a" * 64):
    return MikroTikScriptArtifact(
        file_name="change.rsc",
        script="# test\n/ip/address/print\n",
        script_sha256=script_sha,
        render_sha256="render-001",
        ordered_command_ids=("inventory.1",),
        dry_run_command='/import file-name="change.rsc" verbose=yes dry-run',
    )


class MikroTikApprovalBindingTests(unittest.TestCase):
    def test_approval_binds_exact_script_state_knowledge_and_dry_run(self):
        artifact = _artifact()
        dry_run = MikroTikDryRunEvidence(
            script_sha256=artifact.script_sha256,
            routeros_version="7.24.1",
            passed=True,
        )
        binding = build_approval_binding(
            change_id="CHG-20260914-001",
            routeros_version="7.24.1",
            pre_state_sha256="b" * 64,
            script=artifact,
            dry_run=dry_run,
        )
        self.assertEqual(len(binding.approval_sha256), 64)
        self.assertEqual(len(binding.knowledge_sha256), 64)
        validate_approval_fingerprint(binding, binding.approval_sha256)

    def test_dry_run_for_different_script_is_rejected(self):
        artifact = _artifact()
        dry_run = MikroTikDryRunEvidence(
            script_sha256="c" * 64,
            routeros_version="7.24.1",
            passed=True,
        )
        with self.assertRaises(MikroTikApprovalError):
            build_approval_binding(
                change_id="CHG-1",
                routeros_version="7.24.1",
                pre_state_sha256="b" * 64,
                script=artifact,
                dry_run=dry_run,
            )

    def test_failed_dry_run_cannot_be_approved(self):
        artifact = _artifact()
        dry_run = MikroTikDryRunEvidence(
            script_sha256=artifact.script_sha256,
            routeros_version="7.24.1",
            passed=False,
            errors=("syntax error",),
        )
        with self.assertRaises(MikroTikApprovalError):
            build_approval_binding(
                change_id="CHG-1",
                routeros_version="7.24.1",
                pre_state_sha256="b" * 64,
                script=artifact,
                dry_run=dry_run,
            )

    def test_stale_approval_hash_is_rejected(self):
        artifact = _artifact()
        dry_run = MikroTikDryRunEvidence(
            script_sha256=artifact.script_sha256,
            routeros_version="7.24.1",
            passed=True,
        )
        binding = build_approval_binding(
            change_id="CHG-1",
            routeros_version="7.24.1",
            pre_state_sha256="b" * 64,
            script=artifact,
            dry_run=dry_run,
        )
        with self.assertRaises(MikroTikApprovalError):
            validate_approval_fingerprint(binding, "d" * 64)


if __name__ == "__main__":
    unittest.main()
