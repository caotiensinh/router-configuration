import hashlib
import json
from pathlib import Path
import subprocess
import tempfile
import unittest

from router_configuration.vendors.cisco.c09_remote_lab_readiness import (
    CiscoC09RemoteLabReadinessError,
    build_remote_lab_host_contract,
    probe_remote_lab_host,
)


def canonical_sha256(value: object) -> str:
    return hashlib.sha256(
        json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False, default=str).encode("utf-8")
    ).hexdigest()


def boundary() -> dict:
    item = {
        "schema_version": "cisco-c09-lab-execution-boundary/1",
        "request_id": "REQ-C09-REMOTE-001",
        "source_sha": "1" * 40,
        "target_id": "c8kv-lab-01",
        "model": "C8000V",
        "iosxe_version": "17.18.1a",
        "documentation_train": "17.18",
        "platform_family": "Catalyst 8000V",
        "role": "router",
        "change_id": "CHG-C09-REMOTE-001",
        "approval_sha256": "2" * 64,
        "c08_decision_sha256": "3" * 64,
        "pre_state_sha256": "4" * 64,
        "payload_digest_sha256": "5" * 64,
        "schema_inventory_digest_sha256": "6" * 64,
        "image_source_id": "CISCO-C8000V-INSTALL",
        "image_identity_sha256": "7" * 64,
        "operator_ref": "operator:c09-lab",
        "operator_attestation_sha256": "8" * 64,
        "requested_scenarios": [
            "read_only_discovery",
            "render_validate",
            "configuration_roundtrip",
            "management_survival",
        ],
        "backend_kind": "virtual_appliance",
        "lab_disposable": True,
        "lab_only": True,
        "eligible_for_controlled_lab_execution": True,
        "runtime_transport_present": False,
        "live_execution_observed": False,
        "c09_complete": False,
        "physical_hardware_claimed": False,
        "production_writer_available": False,
        "production_write_authorized": False,
    }
    item["boundary_record_sha256"] = canonical_sha256(item)
    return item


def contract() -> dict:
    return build_remote_lab_host_contract(
        boundary(),
        lab_host_id="lab-host:c09-01",
        provider="qemu_kvm",
        host_attestation_sha256="9" * 64,
    )


SUCCESS_OUTPUT = """probe_schema=cisco-c09-remote-lab-host-probe/1
kvm_present=true
kvm_readable=true
kvm_writable=true
qemu_system_present=true
qemu_img_present=true
virsh_present=false
libvirt_socket_present=false
cpu_vmx_or_svm_present=true
mutation_attempted=false
image_started=false
production_write_authorized=false
"""


class CiscoC09RemoteLabReadinessTests(unittest.TestCase):
    def test_contract_binds_boundary_without_endpoint_or_credentials(self) -> None:
        result = contract()
        self.assertEqual(result["provider"], "qemu_kvm")
        self.assertEqual(result["model"], "C8000V")
        self.assertFalse(result["remote_endpoint_recorded"])
        self.assertFalse(result["credentials_recorded"])
        self.assertTrue(result["strict_host_key_checking_required"])
        self.assertFalse(result["password_authentication_allowed"])
        self.assertFalse(result["production_write_authorized"])
        self.assertNotIn("host", result)
        self.assertNotIn("username", result)
        self.assertEqual(len(result["host_contract_sha256"]), 64)

    def test_tampered_or_unsafe_boundary_fails_closed(self) -> None:
        item = boundary()
        item["target_id"] = "changed"
        with self.assertRaisesRegex(CiscoC09RemoteLabReadinessError, "boundary digest mismatch"):
            build_remote_lab_host_contract(
                item,
                lab_host_id="lab-host:c09-01",
                provider="qemu_kvm",
                host_attestation_sha256="9" * 64,
            )

        item = boundary()
        item["production_write_authorized"] = True
        item["boundary_record_sha256"] = canonical_sha256({k: v for k, v in item.items() if k != "boundary_record_sha256"})
        with self.assertRaisesRegex(CiscoC09RemoteLabReadinessError, "production_write_authorized"):
            build_remote_lab_host_contract(
                item,
                lab_host_id="lab-host:c09-01",
                provider="qemu_kvm",
                host_attestation_sha256="9" * 64,
            )

    def test_only_explicit_remote_virtualization_providers_are_allowed(self) -> None:
        with self.assertRaisesRegex(CiscoC09RemoteLabReadinessError, "unsupported remote lab provider"):
            build_remote_lab_host_contract(
                boundary(),
                lab_host_id="lab-host:c09-01",
                provider="production_hypervisor",
                host_attestation_sha256="9" * 64,
            )

    def test_successful_read_only_probe_reports_remote_host_ready(self) -> None:
        observed = {}

        def fake_runner(command, **kwargs):
            observed["command"] = command
            observed["kwargs"] = kwargs
            return subprocess.CompletedProcess(command, 0, SUCCESS_OUTPUT, "")

        with tempfile.TemporaryDirectory() as temp_dir:
            known_hosts = Path(temp_dir) / "known_hosts"
            known_hosts.write_text("lab.example.invalid ssh-ed25519 AAAATEST\n", encoding="utf-8")
            result = probe_remote_lab_host(
                contract(),
                ssh_host="lab.example.invalid",
                ssh_user="c09lab",
                known_hosts_file=known_hosts,
                runner=fake_runner,
            )

        self.assertTrue(result["ssh_connected"])
        self.assertTrue(result["remote_host_ready"])
        self.assertTrue(result["ready_for_c8000v_image_staging"])
        self.assertFalse(result["mutation_attempted"])
        self.assertFalse(result["image_started"])
        self.assertFalse(result["c09_complete"])
        self.assertFalse(result["production_write_authorized"])
        command = observed["command"]
        self.assertIn("StrictHostKeyChecking=yes", command)
        self.assertIn("PasswordAuthentication=no", command)
        self.assertIn("ClearAllForwardings=yes", command)
        self.assertEqual(command[-2:], ["sh", "-s"])
        self.assertIn("mutation_attempted=false", observed["kwargs"]["input"])

    def test_missing_qemu_is_observed_not_promoted(self) -> None:
        output = SUCCESS_OUTPUT.replace("qemu_system_present=true", "qemu_system_present=false")

        def fake_runner(command, **kwargs):
            return subprocess.CompletedProcess(command, 0, output, "")

        with tempfile.TemporaryDirectory() as temp_dir:
            known_hosts = Path(temp_dir) / "known_hosts"
            known_hosts.write_text("trusted\n", encoding="utf-8")
            result = probe_remote_lab_host(
                contract(),
                ssh_host="10.0.0.10",
                ssh_user="labuser",
                known_hosts_file=known_hosts,
                runner=fake_runner,
            )

        self.assertTrue(result["ssh_connected"])
        self.assertFalse(result["qemu_system_present"])
        self.assertFalse(result["remote_host_ready"])
        self.assertFalse(result["ready_for_c8000v_image_staging"])

    def test_ssh_failure_is_sanitized_and_does_not_echo_endpoint(self) -> None:
        def fake_runner(command, **kwargs):
            return subprocess.CompletedProcess(command, 255, "", "Permission denied (publickey).")

        with tempfile.TemporaryDirectory() as temp_dir:
            known_hosts = Path(temp_dir) / "known_hosts"
            known_hosts.write_text("trusted\n", encoding="utf-8")
            result = probe_remote_lab_host(
                contract(),
                ssh_host="192.0.2.10",
                ssh_user="labuser",
                known_hosts_file=known_hosts,
                runner=fake_runner,
            )

        self.assertFalse(result["ssh_connected"])
        self.assertEqual(result["failure_class"], "authentication_failed")
        serialized = json.dumps(result, sort_keys=True)
        self.assertNotIn("192.0.2.10", serialized)
        self.assertNotIn("labuser", serialized)
        self.assertFalse(result["production_write_authorized"])

    def test_probe_rejects_remote_mutation_claim(self) -> None:
        output = SUCCESS_OUTPUT.replace("mutation_attempted=false", "mutation_attempted=true")

        def fake_runner(command, **kwargs):
            return subprocess.CompletedProcess(command, 0, output, "")

        with tempfile.TemporaryDirectory() as temp_dir:
            known_hosts = Path(temp_dir) / "known_hosts"
            known_hosts.write_text("trusted\n", encoding="utf-8")
            with self.assertRaisesRegex(CiscoC09RemoteLabReadinessError, "crossed mutation boundary"):
                probe_remote_lab_host(
                    contract(),
                    ssh_host="lab.example.invalid",
                    ssh_user="labuser",
                    known_hosts_file=known_hosts,
                    runner=fake_runner,
                )

    def test_trusted_host_key_file_is_mandatory(self) -> None:
        with self.assertRaisesRegex(CiscoC09RemoteLabReadinessError, "trusted known_hosts"):
            probe_remote_lab_host(
                contract(),
                ssh_host="lab.example.invalid",
                ssh_user="labuser",
                known_hosts_file="/definitely/not/present/c09-known-hosts",
            )


if __name__ == "__main__":
    unittest.main()
