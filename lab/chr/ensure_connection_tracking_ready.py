from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any, Mapping

import verify_mutation_rollback as mutation
import verify_render_dry_run as base
import verify_render_dry_run_chunked as chunked


class ConnectionTrackingReadinessError(RuntimeError):
    pass


SCRIPT_FILE = "routercfg-conntrack-readiness.rsc"
VERDICT_FILE = "routercfg-conntrack-readiness-verdict.txt"
TEMP_FILES = (SCRIPT_FILE, VERDICT_FILE)
ENABLE_COMMAND = "/ip/firewall/connection/tracking/set enabled=yes"
OFFICIAL_REFERENCE = "https://manual.mikrotik.com/docs/"


def _settings(admin: base.LoopbackCHRAdmin) -> dict[str, Any]:
    status, payload = admin.request("GET", "ip/firewall/connection/tracking")
    if status != 200:
        raise ConnectionTrackingReadinessError(
            f"connection tracking read-back returned HTTP {status}"
        )
    rows = base._rows(payload)
    if len(rows) != 1:
        raise ConnectionTrackingReadinessError(
            f"connection tracking read-back expected one settings object, observed {len(rows)}"
        )
    row: Mapping[str, Any] = rows[0]
    return {
        "enabled": str(row.get("enabled") or ""),
        "active_ipv4": base._is_true(row.get("active-ipv4")),
        "active_ipv6": base._is_true(row.get("active-ipv6")),
        "max_entries": str(row.get("max-entries") or ""),
        "total_entries": str(row.get("total-entries") or ""),
    }


def ensure_ready(*, admin_url: str, output: Path) -> dict[str, Any]:
    admin = base.LoopbackCHRAdmin(admin_url)
    platform = admin.assert_disposable_chr()
    for name in TEMP_FILES:
        base._delete_file_if_present(admin, name)

    before = _settings(admin)
    import_result: dict[str, Any] | None = None
    try:
        chunked._create_text_file_chunk_verified(
            admin,
            SCRIPT_FILE,
            ENABLE_COMMAND + "\n",
        )
        import_result = mutation._execute_import(
            admin,
            file_name=SCRIPT_FILE,
            expect_success=True,
        )
        after = _settings(admin)
        if after["enabled"] != "yes":
            raise ConnectionTrackingReadinessError(
                "connection tracking did not read back enabled=yes after explicit lab readiness activation"
            )
    finally:
        for name in TEMP_FILES:
            base._delete_file_if_present(admin, name)
        base._assert_files_absent(admin, TEMP_FILES)

    result = {
        "schema_version": "chr-connection-tracking-readiness/1",
        "ok": True,
        "scope": "disposable_chr_packet_flow_lab_only",
        "method": "explicit_routeros_connection_tracking_enable_with_readback",
        "official_reference": OFFICIAL_REFERENCE,
        "platform": {
            "version": str(platform.get("version") or ""),
            "architecture": str(platform.get("architecture-name") or ""),
            "board_name": str(platform.get("board-name") or ""),
        },
        "before": before,
        "after": after,
        "import": import_result,
        "readiness": "enabled_yes_verified",
        "temporary_files_removed": True,
        "ephemeral_target": True,
        "production_writer_available": False,
        "physical_router_targeted": False,
        "write_authorized": False,
    }
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return result


def main() -> int:
    parser = argparse.ArgumentParser(
        description=(
            "Explicitly enable and verify RouterOS connection tracking on disposable CHR "
            "before PCC packet-flow acceptance"
        )
    )
    parser.add_argument("--admin-url", default="http://127.0.0.1:9380")
    parser.add_argument("--output", required=True)
    args = parser.parse_args()
    try:
        result = ensure_ready(admin_url=args.admin_url, output=Path(args.output))
        print(json.dumps(result, indent=2, sort_keys=True))
        return 0
    except (
        OSError,
        base.CHRRenderDryRunError,
        ConnectionTrackingReadinessError,
    ) as exc:
        failure = {
            "schema_version": "chr-connection-tracking-readiness/1",
            "ok": False,
            "error": str(exc),
            "production_writer_available": False,
            "physical_router_targeted": False,
            "write_authorized": False,
        }
        output = Path(args.output)
        output.parent.mkdir(parents=True, exist_ok=True)
        output.write_text(
            json.dumps(failure, indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
        )
        print(json.dumps(failure, indent=2, sort_keys=True))
        return 20


if __name__ == "__main__":
    raise SystemExit(main())
