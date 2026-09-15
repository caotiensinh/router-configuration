from __future__ import annotations

import argparse
import hashlib
import json
import os
import secrets
import string
import subprocess
import time
from pathlib import Path
from typing import Any, Mapping

import verify_render_dry_run as base
import verify_render_dry_run_chunked as chunked

from router_configuration.transaction_backup_evidence import (
    TransactionBackupEvidenceError,
    build_transaction_backup_evidence,
    validate_transaction_backup_evidence,
)
from router_configuration.transaction_backup_set import build_transaction_backup_set


class CHRTransactionBackupAcceptanceError(RuntimeError):
    pass


EXPORT_FILE = "routercfg-prechange-export.rsc"
BACKUP_STEM = "routercfg-prechange-system"
BACKUP_FILE = BACKUP_STEM + ".backup"
FETCH_USER = "routercfg-backup-fetch"


def _workflow_sha(value: str) -> str:
    text = str(value or "").strip().lower()
    if len(text) != 40 or any(ch not in "0123456789abcdef" for ch in text):
        raise CHRTransactionBackupAcceptanceError("workflow SHA must be a full lowercase git SHA-1")
    return text


def _secret(length: int = 40) -> str:
    alphabet = string.ascii_letters + string.digits + "*_"
    return "".join(secrets.choice(alphabet) for _ in range(length))


def _sha256_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def _file_record(admin: base.LoopbackCHRAdmin, name: str) -> Mapping[str, Any] | None:
    _, payload = admin.request("GET", "file")
    for row in base._rows(payload):
        if str(row.get("name") or "") == name:
            return row
    return None


def _wait_file(admin: base.LoopbackCHRAdmin, name: str, *, timeout_seconds: float = 10.0) -> Mapping[str, Any]:
    deadline = time.monotonic() + timeout_seconds
    while time.monotonic() < deadline:
        record = _file_record(admin, name)
        if record is not None:
            return record
        time.sleep(0.1)
    raise CHRTransactionBackupAcceptanceError(f"RouterOS file did not appear: {name}")


def _delete_user(admin: base.LoopbackCHRAdmin, name: str) -> None:
    _, payload = admin.request("GET", "user")
    for row in base._rows(payload):
        if str(row.get("name") or "") != name:
            continue
        row_id = str(row.get(".id") or "").strip()
        if row_id:
            admin.request("DELETE", f"user/{row_id}")


def _assert_user_absent(admin: base.LoopbackCHRAdmin, name: str) -> None:
    _, payload = admin.request("GET", "user")
    if any(str(row.get("name") or "") == name for row in base._rows(payload)):
        raise CHRTransactionBackupAcceptanceError("temporary backup fetch user was not removed")


def _assert_sanitized_export(text: str) -> None:
    lowered = text.lower()
    if not text.strip():
        raise CHRTransactionBackupAcceptanceError("RouterOS sanitized export is empty")
    forbidden_literals = (
        "private-key=",
        "preshared-key=",
        "private_key=",
        "preshared_key=",
    )
    if any(marker in lowered for marker in forbidden_literals):
        raise CHRTransactionBackupAcceptanceError("sanitized export contains a private-key field")
    for line in text.splitlines():
        lowered_line = line.lower()
        for field in ("password=", "secret="):
            if field not in lowered_line:
                continue
            value = lowered_line.split(field, 1)[1].split()[0].strip() if lowered_line.split(field, 1)[1].strip() else ""
            if value not in {"", '""', "***", '"***"'}:
                raise CHRTransactionBackupAcceptanceError(
                    f"sanitized export contains a non-redacted {field[:-1]} value"
                )


def _capture_sanitized_export(
    admin: base.LoopbackCHRAdmin,
    *,
    output: Path,
) -> tuple[str, int]:
    base._delete_file_if_present(admin, EXPORT_FILE)
    status, _ = admin.request(
        "POST",
        "export",
        {"compact": "", "file": EXPORT_FILE},
        allow_http_error=True,
    )
    if status >= 400:
        raise CHRTransactionBackupAcceptanceError(
            f"RouterOS export command failed with HTTP {status}"
        )
    record = _wait_file(admin, EXPORT_FILE)
    text = str(record.get("contents") or "")
    _assert_sanitized_export(text)
    encoded = text.encode("utf-8")
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_bytes(encoded)
    return _sha256_bytes(encoded), len(encoded)


def _capture_encrypted_binary(
    admin: base.LoopbackCHRAdmin,
    *,
    ssh_port: int,
    local_path: Path,
) -> tuple[str, int]:
    fetch_password = _secret()
    backup_password = _secret()
    _delete_user(admin, FETCH_USER)
    base._delete_file_if_present(admin, BACKUP_FILE)
    local_path.unlink(missing_ok=True)

    try:
        admin.request(
            "PUT",
            "user",
            {
                "name": FETCH_USER,
                "group": "full",
                "password": fetch_password,
            },
        )
        status, _ = admin.request(
            "POST",
            "system/backup/save",
            {
                "name": BACKUP_STEM,
                "password": backup_password,
                "encryption": "aes-sha256",
            },
            allow_http_error=True,
        )
        if status >= 400:
            raise CHRTransactionBackupAcceptanceError(
                f"RouterOS encrypted backup command failed with HTTP {status}"
            )
        _wait_file(admin, BACKUP_FILE, timeout_seconds=15.0)

        env = dict(os.environ)
        env["SSHPASS"] = fetch_password
        command = [
            "sshpass",
            "-e",
            "scp",
            "-q",
            "-P",
            str(ssh_port),
            "-o",
            "StrictHostKeyChecking=no",
            "-o",
            "UserKnownHostsFile=/dev/null",
            "-o",
            "ConnectTimeout=10",
            f"{FETCH_USER}@127.0.0.1:/{BACKUP_FILE}",
            str(local_path),
        ]
        completed = subprocess.run(
            command,
            env=env,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=30,
            check=False,
        )
        if completed.returncode != 0:
            raise CHRTransactionBackupAcceptanceError(
                f"encrypted RouterOS backup SCP retrieval failed with exit {completed.returncode}"
            )
        data = local_path.read_bytes()
        if len(data) < 128:
            raise CHRTransactionBackupAcceptanceError("downloaded RouterOS binary backup is unexpectedly small")
        if b"/ip firewall" in data.lower() or b"routercfg:managed" in data.lower():
            raise CHRTransactionBackupAcceptanceError("encrypted backup unexpectedly exposes recognizable plaintext")
        return _sha256_bytes(data), len(data)
    finally:
        local_path.unlink(missing_ok=True)
        base._delete_file_if_present(admin, BACKUP_FILE)
        _delete_user(admin, FETCH_USER)
        _assert_user_absent(admin, FETCH_USER)
        base._assert_files_absent(admin, (BACKUP_FILE,))


def verify_transaction_backup_acceptance(
    *,
    admin_url: str,
    ssh_port: int,
    workflow_sha: str,
    export_output: Path,
) -> dict[str, Any]:
    exact_sha = _workflow_sha(workflow_sha)
    admin = base.LoopbackCHRAdmin(admin_url)
    platform = admin.assert_disposable_chr()

    pre_state = chunked._configuration_snapshot_with_pcc(admin)
    pre_state_sha256 = base._canonical_digest(pre_state)

    export_sha256 = ""
    export_bytes = 0
    backup_sha256 = ""
    backup_bytes = 0
    local_binary = export_output.parent / "routercfg-prechange-system.backup"

    try:
        export_sha256, export_bytes = _capture_sanitized_export(
            admin,
            output=export_output,
        )
        backup_sha256, backup_bytes = _capture_encrypted_binary(
            admin,
            ssh_port=ssh_port,
            local_path=local_binary,
        )

        sanitized = build_transaction_backup_evidence(
            kind="sanitized_export",
            artifact_ref=f"artifact://chr/{exact_sha}/transaction-prechange-export.rsc",
            sha256=export_sha256,
            pre_state_sha256=pre_state_sha256,
        ).as_dict()
        protected = build_transaction_backup_evidence(
            kind="protected_ephemeral_binary",
            artifact_ref=f"protected-ref://chr/{exact_sha}/encrypted-system-backup",
            sha256=backup_sha256,
            pre_state_sha256=pre_state_sha256,
        ).as_dict()
        validate_transaction_backup_evidence(
            sanitized,
            expected_pre_state_sha256=pre_state_sha256,
        )
        validate_transaction_backup_evidence(
            protected,
            expected_pre_state_sha256=pre_state_sha256,
        )
        backup_set = build_transaction_backup_set(
            sanitized_export=sanitized,
            protected_binary=protected,
        ).as_dict()
    finally:
        base._delete_file_if_present(admin, EXPORT_FILE)
        base._assert_files_absent(admin, (EXPORT_FILE, BACKUP_FILE))
        local_binary.unlink(missing_ok=True)
        _delete_user(admin, FETCH_USER)
        _assert_user_absent(admin, FETCH_USER)

    result = {
        "schema_version": "chr-transaction-real-backup-acceptance/1",
        "ok": True,
        "acceptance": "PASS",
        "scope": "disposable_chr_real_dual_prechange_backup_acceptance",
        "workflow_sha": exact_sha,
        "platform": {
            "version": str(platform.get("version") or ""),
            "architecture": str(platform.get("architecture-name") or ""),
            "board_name": str(platform.get("board-name") or ""),
        },
        "pre_state_sha256": pre_state_sha256,
        "sanitized_export": sanitized,
        "protected_binary": protected,
        "backup_set": backup_set,
        "capture_proof": {
            "sanitized_export_bytes": export_bytes,
            "sanitized_export_sha256_from_bytes": True,
            "protected_binary_bytes": backup_bytes,
            "protected_binary_sha256_from_downloaded_bytes": True,
            "protected_binary_encryption_requested": "aes-sha256",
            "backup_password_persisted": False,
            "fetch_password_persisted": False,
            "router_binary_removed": True,
            "runner_binary_removed": True,
            "temporary_fetch_user_removed": True,
            "router_export_removed_after_capture": True,
        },
        "binary_payload_in_repository": False,
        "secret_values_present": False,
        "production_writer_available": False,
        "transport_exposed_to_product": False,
        "physical_router_targeted": False,
        "production_allowed": False,
        "write_authorized": False,
    }
    return result


def main() -> int:
    parser = argparse.ArgumentParser(description="Verify real dual pre-change backup capture on disposable CHR")
    parser.add_argument("--admin-url", default="http://127.0.0.1:9780")
    parser.add_argument("--ssh-port", type=int, default=9822)
    parser.add_argument("--workflow-sha", required=True)
    parser.add_argument("--export-output", required=True)
    parser.add_argument("--output", required=True)
    args = parser.parse_args()

    output = Path(args.output)
    output.parent.mkdir(parents=True, exist_ok=True)
    try:
        result = verify_transaction_backup_acceptance(
            admin_url=args.admin_url,
            ssh_port=args.ssh_port,
            workflow_sha=args.workflow_sha,
            export_output=Path(args.export_output),
        )
        rc = 0
    except (
        OSError,
        subprocess.SubprocessError,
        base.CHRRenderDryRunError,
        TransactionBackupEvidenceError,
        CHRTransactionBackupAcceptanceError,
        ValueError,
    ) as exc:
        result = {
            "schema_version": "chr-transaction-real-backup-acceptance/1",
            "ok": False,
            "acceptance": "FAIL",
            "error_class": exc.__class__.__name__,
            "production_writer_available": False,
            "transport_exposed_to_product": False,
            "physical_router_targeted": False,
            "production_allowed": False,
            "write_authorized": False,
        }
        rc = 18

    output.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(json.dumps(result, indent=2, sort_keys=True))
    return rc


if __name__ == "__main__":
    raise SystemExit(main())
