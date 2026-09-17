from pathlib import Path
import unittest


WORKFLOW = Path(".github/workflows/cisco-c09-remote-lab-readiness.yml")


class CiscoC09RemoteLabReadinessWorkflowTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.text = WORKFLOW.read_text(encoding="utf-8")

    def test_owner_preserving_runtime_surfaces_are_explicit(self) -> None:
        self.assertIn("workflow_dispatch:", self.text)
        self.assertIn("workflow_call:", self.text)
        self.assertIn("runs-on: self-hosted", self.text)
        self.assertIn("aiserver-router-configuration", self.text)
        self.assertIn("github.repository == 'caotiensinh/router-configuration'", self.text)
        self.assertNotIn("runs-on: ubuntu-latest", self.text)

    def test_exact_source_is_checked_out_without_persisted_token(self) -> None:
        self.assertIn("ref: ${{ inputs.expected_source_sha }}", self.text)
        self.assertIn("persist-credentials: false", self.text)
        self.assertIn('test "$(git rev-parse HEAD)" = "${EXPECTED_SOURCE_SHA}"', self.text)

    def test_remote_credentials_use_explicit_least_privilege_secret_names(self) -> None:
        for name in (
            "C09_REMOTE_LAB_HOST",
            "C09_REMOTE_LAB_USER",
            "C09_REMOTE_LAB_KNOWN_HOSTS_B64",
            "C09_REMOTE_LAB_SSH_KEY_B64",
        ):
            self.assertIn(name, self.text)
        self.assertNotIn("secrets: inherit", self.text)
        self.assertIn("secret_values_recorded", self.text)
        self.assertIn('"secret_values_recorded": False', self.text)

    def test_private_material_is_ephemeral_and_removed_before_upload(self) -> None:
        materialize = self.text.index("Materialize ephemeral SSH trust and identity files")
        probe = self.text.index("Run fixed read-only remote readiness probe")
        cleanup = self.text.index("Remove ephemeral SSH material")
        upload = self.text.index("Upload sanitized readiness evidence")
        self.assertLess(materialize, probe)
        self.assertLess(probe, cleanup)
        self.assertLess(cleanup, upload)
        self.assertIn("umask 077", self.text)
        self.assertIn("os.chmod(path, 0o600)", self.text)
        self.assertIn('rm -f "${RUNNER_TEMP}/c09-remote-lab/known_hosts"', self.text)
        self.assertNotIn("id_c09_lab\n          retention", self.text)

    def test_workflow_calls_only_readiness_module_and_never_local_virtualization(self) -> None:
        self.assertIn(
            "python -m router_configuration.vendors.cisco.c09_remote_lab_readiness",
            self.text,
        )
        for forbidden in (
            "sudo ",
            "docker run",
            "qemu-system-x86_64 ",
            "qemu-img create",
            "virsh start",
            "virt-install",
            "edit-config",
            "confirmed-commit",
        ):
            self.assertNotIn(forbidden, self.text)

    def test_readiness_cannot_claim_c09_or_production_completion(self) -> None:
        self.assertIn('record.get("remote_host_ready") is not True', self.text)
        self.assertIn('record.get("production_write_authorized") is not False', self.text)
        self.assertNotIn('"c09_complete": True', self.text)
        self.assertNotIn('"production_write_authorized": True', self.text)

    def test_preflight_runs_before_any_remote_probe(self) -> None:
        record = self.text.index("Record sanitized secret preflight")
        enforce = self.text.index("Enforce secret preflight before SSH access")
        probe = self.text.index("Run fixed read-only remote readiness probe")
        self.assertLess(record, enforce)
        self.assertLess(enforce, probe)


if __name__ == "__main__":
    unittest.main()
