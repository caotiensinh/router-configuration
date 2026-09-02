from __future__ import annotations

import argparse
import hashlib
import json
import re
import time
from pathlib import Path
from typing import Any, Mapping

import verify_render_dry_run as base


class CHRRecoveryExportError(RuntimeError):
    pass


EXPORT_STEM = "routercfg-recovery-export"
EXPORT_FILE = EXPORT_STEM + ".rsc"
_SENSITIVE_ASSIGNMENT = re.compile(
    r"(?i)(?:password|private-key|preshared-key|pre-shared-key|ipsec-secret|secret|token)\s*=\s*(?:\"([^\"]*)\"|([^\s;]+))"
)
_MASKED_VALUES = {"", "<hidden>", "***", "*****", "[redacted]", "redacted"}


def _wait_for_export(admin: base.LoopbackCHRAdmin, timeout_seconds: float = 15.0) -> Mapping[str, Any]:
    deadline = time.monotonic() + timeout_seconds
    while time.monotonic() < deadline:
        record = base._file_record(admin, EXPORT_FILE)
        if record is not None:
            return record
        time.sleep(0.25)
    raise CHRRecoveryExportError("RouterOS sanitized export file was not created")


def _unsafe_sensitive_assignments(text: str) -> list[str]:
    hits: list[str] = []
    for match in _SENSITIVE_ASSIGNMENT.finditer(text):
        value = (match.group(1) if match.group(1) is not None else match.group(2) or "").strip()
        if value.lower() not in _MASKED_VALUES:
            key = match.group(0).split("=", 1)[0].strip().lower()
            hits.append(key)
    return sorted(set(hits))


def verify(*, admin_url: str) -> dict[str, Any]:
    admin = base.LoopbackCHRAdmin(admin_url)
    platform = admin.assert_disposable_chr()
    base._delete_file_if_present(admin, EXPORT_FILE)

    pre_state = base._configuration_snapshot(admin)
    pre_state_sha = base._canonical_digest(pre_state)
    export_contents = ""
    try:
        status, response = admin.request(
            "POST",
            "execute",
            {"script": f"/export file={EXPORT_STEM} show-sensitive=no"},
            allow_http_error=True,
        )
        if status >= 400:
            raise CHRRecoveryExportError(
                f"RouterOS export command failed to start with HTTP {status}: {str(response)[:300]}"
            )
        record = _wait_for_export(admin)
        export_contents = str(record.get("contents") or "")
        if not export_contents.strip():
            file_id = str(record.get(".id") or "").strip()
            if file_id:
                _, detail = admin.request("GET", f"file/{file_id}")
                if isinstance(detail, Mapping):
                    export_contents = str(detail.get("contents") or "")
        if not export_contents.strip():
            raise CHRRecoveryExportError("RouterOS sanitized export file is empty or unreadable through lab REST")

        unsafe = _unsafe_sensitive_assignments(export_contents)
        if unsafe:
            raise CHRRecoveryExportError(
                "sanitized export contains unmasked sensitive assignments: " + ", ".join(unsafe)
            )
        export_sha = hashlib.sha256(export_contents.encode("utf-8")).hexdigest()
        post_state_sha = base._canonical_digest(base._configuration_snapshot(admin))
        if post_state_sha != pre_state_sha:
            raise CHRRecoveryExportError("sanitized export changed RouterOS configuration state")
    finally:
        base._delete_file_if_present(admin, EXPORT_FILE)
        if base._file_record(admin, EXPORT_FILE) is not None:
            raise CHRRecoveryExportError("temporary recovery export file was not removed")

    return {
        "ok": True,
        "acceptance": "PASS",
        "scope": "disposable_chr_sanitized_recovery_export_evidence",
        "platform": {
            "version": str(platform.get("version") or ""),
            "architecture": str(platform.get("architecture-name") or ""),
            "board_name": str(platform.get("board-name") or ""),
        },
        "recovery_export": {
            "format": "routeros_rsc_text",
            "show_sensitive": False,
            "contents_persisted_to_ci_artifact": False,
            "sha256": export_sha,
            "size_bytes": len(export_contents.encode("utf-8")),
            "unsafe_sensitive_assignment_count": 0,
            "temporary_file_removed": True,
        },
        "pre_state_sha256": pre_state_sha,
        "post_state_sha256": post_state_sha,
        "configuration_unchanged": post_state_sha == pre_state_sha,
        "binary_backup_created": False,
        "binary_backup_persisted": False,
        "production_backup_complete": False,
        "production_writer_available": False,
        "transport_exposed_to_product": False,
        "write_authorized": False,
        "physical_router_targeted": False,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description="Validate sanitized RouterOS recovery export evidence on disposable CHR")
    parser.add_argument("--admin-url", default="http://127.0.0.1:9682")
    parser.add_argument("--output", required=True)
    args = parser.parse_args()
    output = Path(args.output)
    output.parent.mkdir(parents=True, exist_ok=True)
    try:
        result = verify(admin_url=args.admin_url)
        rc = 0
    except Exception as exc:
        result = {
            "ok": False,
            "acceptance": "FAIL",
            "error": str(exc),
            "binary_backup_created": False,
            "binary_backup_persisted": False,
            "production_backup_complete": False,
            "production_writer_available": False,
            "transport_exposed_to_product": False,
            "write_authorized": False,
            "physical_router_targeted": False,
        }
        rc = 15
    output.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(json.dumps(result, indent=2, sort_keys=True))
    return rc


if __name__ == "__main__":
    raise SystemExit(main())
