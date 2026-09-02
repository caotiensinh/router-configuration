import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
WORKFLOW = ROOT / ".github" / "workflows" / "chr-clean-admission.yml"


class CHRCleanWorkflowContractTests(unittest.TestCase):
    def setUp(self):
        self.source = WORKFLOW.read_text(encoding="utf-8")

    def test_workflow_requires_explicit_clean_trigger(self):
        self.assertIn("ci(chr-clean):", self.source)
        self.assertIn("github.ref == 'refs/heads/main'", self.source)

    def test_preparation_uses_overlay_and_acceptance_uses_fresh_snapshot_boot(self):
        self.assertIn("qemu-img create -f qcow2 -F raw -b /tmp/chr.img /tmp/chr-prepared.qcow2", self.source)
        self.assertIn("Boot preparation VM with writable overlay", self.source)
        self.assertIn("Stop preparation VM and validate overlay", self.source)
        self.assertIn("Boot fresh clean admission VM in snapshot mode", self.source)
        clean_boot = self.source.split("- name: Boot fresh clean admission VM in snapshot mode", 1)[1]
        self.assertIn("-snapshot", clean_boot)
        self.assertIn("file=/tmp/chr-prepared.qcow2,format=qcow2", clean_boot)

    def test_clean_phase_contains_no_admin_http_or_fixture_mutator(self):
        clean_phase = self.source.split("- name: Boot fresh clean admission VM in snapshot mode", 1)[1]
        self.assertNotIn("http://127.0.0.1:9180", clean_phase)
        self.assertNotIn("populate_acceptance_objects.py", clean_phase)
        self.assertNotIn("verify_reader_write_denied.py", clean_phase)
        self.assertNotIn("bootstrap_secure_acceptance.py", clean_phase)
        self.assertIn("https://127.0.0.1:9443/rest/system/resource", clean_phase)
        self.assertIn("routerctl routeros-discover", clean_phase)
        self.assertIn("routerctl routeros-evidence-check", clean_phase)

    def test_image_overlay_and_credentials_are_never_artifactized(self):
        artifact = self.source.split("- name: Preserve clean admission evidence only", 1)[1]
        self.assertNotIn("/tmp/chr.img", artifact)
        self.assertNotIn("/tmp/chr.img.zip", artifact)
        self.assertNotIn("/tmp/chr-prepared.qcow2", artifact)
        self.assertNotIn("/tmp/chr-clean-reader-credentials.json", artifact.split("- name: Delete ephemeral credentials", 1)[0])
        self.assertIn("rm -f /tmp/chr-clean-reader-credentials.json", self.source)

    def test_clean_evaluator_and_machine_provenance_are_required(self):
        self.assertIn("build_ci_provenance_record.py", self.source)
        self.assertIn("build_clean_execution_manifest.py", self.source)
        self.assertIn("evaluate_clean_admission.py", self.source)
        self.assertIn("--no-install-recommends", self.source)


if __name__ == "__main__":
    unittest.main()
