from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any

import verify_render_dry_run as base
import verify_render_dry_run_chunked as chunked


def diagnose(*, admin_url: str, script_path: Path) -> dict[str, Any]:
    admin = base.LoopbackCHRAdmin(admin_url)
    platform = admin.assert_disposable_chr()
    lines = [line for line in script_path.read_text(encoding="utf-8").splitlines() if line.strip()]
    if not lines:
        raise base.CHRRenderDryRunError("diagnostic input script is empty")

    before = base._configuration_snapshot(admin)
    before_digest = base._canonical_digest(before)
    results: list[dict[str, Any]] = []

    for index, command in enumerate(lines, start=1):
        script_name = f"routercfg-diag-{index:03d}.rsc"
        verdict_name = f"routercfg-diag-{index:03d}.txt"
        try:
            chunked._create_text_file_chunk_verified(admin, script_name, command + "\n")
            chunked._create_text_file_chunk_verified(admin, verdict_name, "PENDING")
            try:
                detail = base._execute_import_dry_run(
                    admin,
                    file_name=script_name,
                    verdict_name=verdict_name,
                    expect_success=True,
                )
                results.append(
                    {
                        "index": index,
                        "ok": True,
                        "command": command,
                        "verdict": detail.get("verdict"),
                    }
                )
            except base.CHRRenderDryRunError as exc:
                results.append(
                    {
                        "index": index,
                        "ok": False,
                        "command": command,
                        "error": str(exc),
                    }
                )
        finally:
            base._delete_file_if_present(admin, script_name)
            base._delete_file_if_present(admin, verdict_name)
            base._assert_files_absent(admin, (script_name, verdict_name))

    after = base._configuration_snapshot(admin)
    after_digest = base._canonical_digest(after)
    if after_digest != before_digest:
        raise base.CHRRenderDryRunError(
            "RouterOS configuration changed during per-command import dry-run diagnostics"
        )

    failed = [item for item in results if not item["ok"]]
    return {
        "ok": not failed,
        "scope": "disposable_chr_per_command_syntax_diagnostics",
        "platform": {
            "version": platform.get("version"),
            "architecture": platform.get("architecture-name"),
            "board_name": platform.get("board-name"),
        },
        "command_count": len(results),
        "failed_count": len(failed),
        "failed_indexes": [item["index"] for item in failed],
        "results": results,
        "configuration_before_sha256": before_digest,
        "configuration_after_sha256": after_digest,
        "configuration_changed": False,
        "temporary_files_removed": True,
        "lab_setup_write_operations_performed": True,
        "production_writer_available": False,
        "write_authorized": False,
    }


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Isolate RouterOS import dry-run syntax failures one generated command at a time"
    )
    parser.add_argument("--admin-url", default="http://127.0.0.1:9180")
    parser.add_argument("--script", required=True)
    parser.add_argument("--output", required=True)
    args = parser.parse_args()

    output = Path(args.output)
    output.parent.mkdir(parents=True, exist_ok=True)
    try:
        result = diagnose(admin_url=args.admin_url, script_path=Path(args.script))
        rc = 0 if result["ok"] else 14
    except (OSError, base.CHRRenderDryRunError) as exc:
        result = {"ok": False, "error": str(exc)}
        rc = 14

    output.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(json.dumps(result, indent=2, sort_keys=True))
    return rc


if __name__ == "__main__":
    raise SystemExit(main())
