"""Fail-closed remote-host readiness probe for Cisco C09 virtual lab execution.

The self-hosted GitHub runner is an orchestrator only.  This module validates an
already-approved C09 execution boundary, binds it to an opaque remote lab-host
identity, and performs a fixed read-only SSH readiness probe.  It never uploads
or starts a Cisco image, changes a remote host, executes IOS XE configuration,
or grants production write authority.
"""

from __future__ import annotations

import argparse
import hashlib
import hmac
import json
import os
from pathlib import Path
import re
import subprocess
from typing import Any, Callable, Mapping, Sequence

_BOUNDARY_SCHEMA = "cisco-c09-lab-execution-boundary/1"
_HOST_CONTRACT_SCHEMA = "cisco-c09-remote-lab-host-contract/1"
_PROBE_SCHEMA = "cisco-c09-remote-lab-host-probe/1"
_READINESS_SCHEMA = "cisco-c09-remote-lab-readiness/1"
_SUPPORTED_PROVIDERS = frozenset({"qemu_kvm", "proxmox_qemu"})
_SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
_REF_RE = re.compile(r"^[A-Za-z0-9_.:@/-]{1,160}$")
_USER_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_.-]{0,63}$")
_HOST_RE = re.compile(r"^[A-Za-z0-9_.:-]{1,253}$")

_REMOTE_PROBE_SCRIPT = r'''set -eu
bool() { if "$@" >/dev/null 2>&1; then printf 'true'; else printf 'false'; fi; }
printf 'probe_schema=cisco-c09-remote-lab-host-probe/1\n'
printf 'kvm_present='; bool test -e /dev/kvm; printf '\n'
printf 'kvm_readable='; bool test -r /dev/kvm; printf '\n'
printf 'kvm_writable='; bool test -w /dev/kvm; printf '\n'
printf 'qemu_system_present='; bool command -v qemu-system-x86_64; printf '\n'
printf 'qemu_img_present='; bool command -v qemu-img; printf '\n'
printf 'virsh_present='; bool command -v virsh; printf '\n'
printf 'libvirt_socket_present='; bool test -S /var/run/libvirt/libvirt-sock; printf '\n'
printf 'cpu_vmx_or_svm_present='; if grep -Ewm1 '(vmx|svm)' /proc/cpuinfo >/dev/null 2>&1; then printf 'true'; else printf 'false'; fi; printf '\n'
printf 'mutation_attempted=false\n'
printf 'image_started=false\n'
printf 'production_write_authorized=false\n'
'''


class CiscoC09RemoteLabReadinessError(ValueError):
    """Raised when a remote C09 lab host cannot be safely probed."""


def _canonical_sha256(value: object) -> str:
    raw = json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        default=str,
    ).encode("utf-8")
    return hashlib.sha256(raw).hexdigest()


def _sha256(value: object, label: str) -> str:
    text = str(value or "").strip().lower()
    if not _SHA256_RE.fullmatch(text):
        raise CiscoC09RemoteLabReadinessError(f"{label} must be lowercase SHA-256")
    return text


def _ref(value: object, label: str) -> str:
    text = str(value or "").strip()
    if not _REF_RE.fullmatch(text):
        raise CiscoC09RemoteLabReadinessError(f"invalid {label}")
    lowered = text.lower()
    if any(marker in lowered for marker in ("password", "token", "secret", "private_key", "http://", "https://")):
        raise CiscoC09RemoteLabReadinessError(f"{label} contains endpoint or secret material")
    return text


def _verify_boundary(boundary: Mapping[str, Any]) -> str:
    if boundary.get("schema_version") != _BOUNDARY_SCHEMA:
        raise CiscoC09RemoteLabReadinessError("unexpected C09 execution boundary schema")
    supplied = _sha256(boundary.get("boundary_record_sha256"), "boundary_record_sha256")
    unsigned = dict(boundary)
    unsigned.pop("boundary_record_sha256", None)
    if not hmac.compare_digest(supplied, _canonical_sha256(unsigned)):
        raise CiscoC09RemoteLabReadinessError("C09 execution boundary digest mismatch")
    if boundary.get("eligible_for_controlled_lab_execution") is not True:
        raise CiscoC09RemoteLabReadinessError("C09 execution boundary is not execution eligible")
    if boundary.get("platform_family") != "Catalyst 8000V" or boundary.get("backend_kind") != "virtual_appliance":
        raise CiscoC09RemoteLabReadinessError("remote C09 lab is bounded to Catalyst 8000V virtual appliance")
    for field in (
        "runtime_transport_present",
        "live_execution_observed",
        "c09_complete",
        "physical_hardware_claimed",
        "production_writer_available",
        "production_write_authorized",
    ):
        if boundary.get(field) is not False:
            raise CiscoC09RemoteLabReadinessError(f"C09 execution boundary crossed safety boundary: {field}")
    return supplied


def build_remote_lab_host_contract(
    boundary: Mapping[str, Any],
    *,
    lab_host_id: str,
    provider: str,
    host_attestation_sha256: str,
) -> dict[str, Any]:
    """Bind a C09 boundary to an opaque remote lab host without recording its endpoint."""

    boundary_sha = _verify_boundary(boundary)
    host_id = _ref(lab_host_id, "lab_host_id")
    normalized_provider = str(provider or "").strip().lower()
    if normalized_provider not in _SUPPORTED_PROVIDERS:
        raise CiscoC09RemoteLabReadinessError("unsupported remote lab provider")
    attestation = _sha256(host_attestation_sha256, "host_attestation_sha256")

    result = {
        "schema_version": _HOST_CONTRACT_SCHEMA,
        "lab_host_id": host_id,
        "provider": normalized_provider,
        "host_attestation_sha256": attestation,
        "boundary_record_sha256": boundary_sha,
        "source_sha": str(boundary.get("source_sha", "")),
        "target_id": str(boundary.get("target_id", "")),
        "model": str(boundary.get("model", "")),
        "iosxe_version": str(boundary.get("iosxe_version", "")),
        "transport": "ssh",
        "remote_endpoint_recorded": False,
        "credentials_recorded": False,
        "strict_host_key_checking_required": True,
        "password_authentication_allowed": False,
        "eligible_for_readiness_probe": True,
        "remote_host_ready": False,
        "image_staged": False,
        "live_execution_observed": False,
        "c09_complete": False,
        "physical_hardware_claimed": False,
        "production_writer_available": False,
        "production_write_authorized": False,
    }
    result["host_contract_sha256"] = _canonical_sha256(result)
    return result


def _verify_host_contract(contract: Mapping[str, Any]) -> str:
    if contract.get("schema_version") != _HOST_CONTRACT_SCHEMA:
        raise CiscoC09RemoteLabReadinessError("unexpected remote lab host contract schema")
    supplied = _sha256(contract.get("host_contract_sha256"), "host_contract_sha256")
    unsigned = dict(contract)
    unsigned.pop("host_contract_sha256", None)
    if not hmac.compare_digest(supplied, _canonical_sha256(unsigned)):
        raise CiscoC09RemoteLabReadinessError("remote lab host contract digest mismatch")
    if contract.get("eligible_for_readiness_probe") is not True:
        raise CiscoC09RemoteLabReadinessError("remote lab host contract is not probe eligible")
    if contract.get("transport") != "ssh" or contract.get("strict_host_key_checking_required") is not True:
        raise CiscoC09RemoteLabReadinessError("remote lab host contract weakens SSH trust boundary")
    if contract.get("password_authentication_allowed") is not False:
        raise CiscoC09RemoteLabReadinessError("password authentication must remain disabled")
    for field in (
        "remote_endpoint_recorded",
        "credentials_recorded",
        "remote_host_ready",
        "image_staged",
        "live_execution_observed",
        "c09_complete",
        "physical_hardware_claimed",
        "production_writer_available",
        "production_write_authorized",
    ):
        if contract.get(field) is not False:
            raise CiscoC09RemoteLabReadinessError(f"remote lab host contract crossed safety boundary: {field}")
    return supplied


def _validate_endpoint(host: str, user: str, port: int) -> tuple[str, str, int]:
    normalized_host = str(host or "").strip()
    normalized_user = str(user or "").strip()
    if not _HOST_RE.fullmatch(normalized_host) or normalized_host.startswith("-"):
        raise CiscoC09RemoteLabReadinessError("invalid remote lab host")
    if not _USER_RE.fullmatch(normalized_user):
        raise CiscoC09RemoteLabReadinessError("invalid remote lab SSH user")
    try:
        normalized_port = int(port)
    except (TypeError, ValueError) as exc:
        raise CiscoC09RemoteLabReadinessError("invalid remote lab SSH port") from exc
    if normalized_port < 1 or normalized_port > 65535:
        raise CiscoC09RemoteLabReadinessError("invalid remote lab SSH port")
    return normalized_host, normalized_user, normalized_port


def _parse_probe_output(stdout: str) -> dict[str, bool]:
    raw: dict[str, str] = {}
    for line in str(stdout or "").splitlines():
        if "=" not in line:
            continue
        key, value = line.split("=", 1)
        raw[key.strip()] = value.strip()
    if raw.get("probe_schema") != _PROBE_SCHEMA:
        raise CiscoC09RemoteLabReadinessError("remote lab probe returned unexpected schema")
    required = (
        "kvm_present",
        "kvm_readable",
        "kvm_writable",
        "qemu_system_present",
        "qemu_img_present",
        "virsh_present",
        "libvirt_socket_present",
        "cpu_vmx_or_svm_present",
        "mutation_attempted",
        "image_started",
        "production_write_authorized",
    )
    result: dict[str, bool] = {}
    for key in required:
        value = raw.get(key)
        if value not in {"true", "false"}:
            raise CiscoC09RemoteLabReadinessError(f"remote lab probe returned invalid boolean: {key}")
        result[key] = value == "true"
    if result["mutation_attempted"] or result["image_started"] or result["production_write_authorized"]:
        raise CiscoC09RemoteLabReadinessError("remote lab readiness probe crossed mutation boundary")
    return result


def _classify_ssh_failure(stderr: str) -> str:
    lowered = str(stderr or "").lower()
    if "host key verification failed" in lowered:
        return "host_key_verification_failed"
    if "permission denied" in lowered:
        return "authentication_failed"
    if "connection timed out" in lowered or "operation timed out" in lowered:
        return "connection_timeout"
    if "connection refused" in lowered:
        return "connection_refused"
    if "no route to host" in lowered or "network is unreachable" in lowered:
        return "network_unreachable"
    return "ssh_failed"


def probe_remote_lab_host(
    contract: Mapping[str, Any],
    *,
    ssh_host: str,
    ssh_user: str,
    known_hosts_file: str | Path,
    ssh_port: int = 22,
    identity_file: str | Path | None = None,
    timeout_seconds: int = 10,
    runner: Callable[..., subprocess.CompletedProcess[str]] = subprocess.run,
) -> dict[str, Any]:
    """Run one fixed, read-only SSH probe and return sanitized readiness evidence."""

    contract_sha = _verify_host_contract(contract)
    host, user, port = _validate_endpoint(ssh_host, ssh_user, ssh_port)
    known_hosts = Path(known_hosts_file)
    if not known_hosts.is_file():
        raise CiscoC09RemoteLabReadinessError("trusted known_hosts file is required")
    identity: Path | None = None
    if identity_file not in (None, ""):
        identity = Path(identity_file)
        if not identity.is_file():
            raise CiscoC09RemoteLabReadinessError("SSH identity file does not exist")
    if not isinstance(timeout_seconds, int) or timeout_seconds < 1 or timeout_seconds > 60:
        raise CiscoC09RemoteLabReadinessError("timeout_seconds must be between 1 and 60")

    command: list[str] = [
        "ssh",
        "-p",
        str(port),
        "-o",
        "BatchMode=yes",
        "-o",
        "StrictHostKeyChecking=yes",
        "-o",
        f"UserKnownHostsFile={known_hosts}",
        "-o",
        "PasswordAuthentication=no",
        "-o",
        "KbdInteractiveAuthentication=no",
        "-o",
        "ClearAllForwardings=yes",
        "-o",
        "ForwardAgent=no",
        "-o",
        "ForwardX11=no",
        "-o",
        "PermitLocalCommand=no",
        "-o",
        f"ConnectTimeout={timeout_seconds}",
        "-o",
        "LogLevel=ERROR",
    ]
    if identity is not None:
        command.extend(["-o", "IdentitiesOnly=yes", "-i", str(identity)])
    command.extend([f"{user}@{host}", "sh", "-s"])

    try:
        completed = runner(
            command,
            input=_REMOTE_PROBE_SCRIPT,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=timeout_seconds + 5,
            check=False,
        )
    except subprocess.TimeoutExpired:
        completed = subprocess.CompletedProcess(command, 124, "", "connection timed out")

    if completed.returncode != 0:
        result = {
            "schema_version": _READINESS_SCHEMA,
            "lab_host_id": str(contract.get("lab_host_id", "")),
            "provider": str(contract.get("provider", "")),
            "host_contract_sha256": contract_sha,
            "ssh_connected": False,
            "failure_class": _classify_ssh_failure(completed.stderr),
            "kvm_present": False,
            "kvm_readable": False,
            "kvm_writable": False,
            "cpu_virtualization_present": False,
            "qemu_system_present": False,
            "qemu_img_present": False,
            "virsh_present": False,
            "libvirt_socket_present": False,
            "remote_host_ready": False,
            "ready_for_c8000v_image_staging": False,
            "remote_endpoint_recorded": False,
            "credentials_recorded": False,
            "mutation_attempted": False,
            "image_started": False,
            "live_execution_observed": False,
            "c09_complete": False,
            "physical_hardware_claimed": False,
            "production_writer_available": False,
            "production_write_authorized": False,
        }
    else:
        observed = _parse_probe_output(completed.stdout)
        ready = all(
            observed[key]
            for key in (
                "kvm_present",
                "kvm_readable",
                "kvm_writable",
                "cpu_vmx_or_svm_present",
                "qemu_system_present",
                "qemu_img_present",
            )
        )
        result = {
            "schema_version": _READINESS_SCHEMA,
            "lab_host_id": str(contract.get("lab_host_id", "")),
            "provider": str(contract.get("provider", "")),
            "host_contract_sha256": contract_sha,
            "ssh_connected": True,
            "failure_class": None,
            "kvm_present": observed["kvm_present"],
            "kvm_readable": observed["kvm_readable"],
            "kvm_writable": observed["kvm_writable"],
            "cpu_virtualization_present": observed["cpu_vmx_or_svm_present"],
            "qemu_system_present": observed["qemu_system_present"],
            "qemu_img_present": observed["qemu_img_present"],
            "virsh_present": observed["virsh_present"],
            "libvirt_socket_present": observed["libvirt_socket_present"],
            "remote_host_ready": ready,
            "ready_for_c8000v_image_staging": ready,
            "remote_endpoint_recorded": False,
            "credentials_recorded": False,
            "mutation_attempted": False,
            "image_started": False,
            "live_execution_observed": False,
            "c09_complete": False,
            "physical_hardware_claimed": False,
            "production_writer_available": False,
            "production_write_authorized": False,
        }
    result["readiness_record_sha256"] = _canonical_sha256(result)
    return result


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Probe a remote Cisco C09 lab host without mutating it")
    parser.add_argument("contract_json")
    args = parser.parse_args(argv)

    contract = json.loads(Path(args.contract_json).read_text(encoding="utf-8"))
    host = os.environ.get("C09_REMOTE_LAB_HOST", "")
    user = os.environ.get("C09_REMOTE_LAB_USER", "")
    port = int(os.environ.get("C09_REMOTE_LAB_PORT", "22"))
    known_hosts = os.environ.get("C09_REMOTE_LAB_KNOWN_HOSTS_FILE", "")
    identity = os.environ.get("C09_REMOTE_LAB_IDENTITY_FILE")
    result = probe_remote_lab_host(
        contract,
        ssh_host=host,
        ssh_user=user,
        ssh_port=port,
        known_hosts_file=known_hosts,
        identity_file=identity,
    )
    print(json.dumps(result, sort_keys=True))
    return 0 if result["remote_host_ready"] else 2


if __name__ == "__main__":
    raise SystemExit(main())
