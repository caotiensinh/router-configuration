from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any, Mapping

import verify_mutation_rollback as mutation
import verify_render_dry_run as base
import verify_render_dry_run_chunked as chunked


class PccRuntimeDiagnosticError(RuntimeError):
    pass


PREFIX = "routercfg:diagnostic:pcc:"
SCRIPT_FILE = "routercfg-pcc-runtime-diagnostic.rsc"
VERDICT_FILE = "routercfg-pcc-runtime-diagnostic-verdict.txt"
TEMP_FILES = (SCRIPT_FILE, VERDICT_FILE)


def _bool(value: Any) -> bool:
    return base._is_true(value)


def _mangle_rows(admin: base.LoopbackCHRAdmin) -> list[dict[str, Any]]:
    _, payload = admin.request("GET", "ip/firewall/mangle")
    return [dict(row) for row in base._rows(payload)]


def _delete_diagnostics(admin: base.LoopbackCHRAdmin) -> None:
    for row in _mangle_rows(admin):
        if not str(row.get("comment") or "").startswith(PREFIX):
            continue
        row_id = str(row.get(".id") or "").strip()
        if row_id:
            admin.request("DELETE", f"ip/firewall/mangle/{row_id}")


def _summary(row: Mapping[str, Any]) -> dict[str, Any]:
    return {
        "id": str(row.get(".id") or ""),
        "comment": str(row.get("comment") or ""),
        "action": str(row.get("action") or ""),
        "invalid": _bool(row.get("invalid")),
        "disabled": _bool(row.get("disabled")),
        "chain": str(row.get("chain") or ""),
        "connection_state": str(row.get("connection-state") or ""),
        "connection_mark": str(row.get("connection-mark") or ""),
        "dst_address_type": str(row.get("dst-address-type") or ""),
        "in_interface_list": str(row.get("in-interface-list") or ""),
        "new_connection_mark": str(row.get("new-connection-mark") or ""),
        "new_routing_mark": str(row.get("new-routing-mark") or ""),
        "pcc": str(row.get("per-connection-classifier") or ""),
    }


def _routing_tables(admin: base.LoopbackCHRAdmin) -> list[dict[str, Any]]:
    _, payload = admin.request("GET", "routing/table")
    result: list[dict[str, Any]] = []
    for row in base._rows(payload):
        name = str(row.get("name") or "")
        if name not in {"main", "to-lab-wan10g", "to-lab-wan1g"}:
            continue
        result.append(
            {
                "name": name,
                "fib": _bool(row.get("fib")),
                "disabled": _bool(row.get("disabled")),
                "invalid": _bool(row.get("invalid")),
            }
        )
    result.sort(key=lambda row: row["name"])
    return result


def _diagnostic_commands() -> tuple[tuple[str, str], ...]:
    """Return incremental CLI variants so one field at a time can be isolated."""

    common = "chain=prerouting action=mark-connection new-connection-mark=diag-common passthrough=yes"
    return (
        (
            "mc_pcc_11_0_min",
            f'/ip/firewall/mangle/add {common} per-connection-classifier="both-addresses-and-ports:11/0" comment="{PREFIX}mc_pcc_11_0_min"',
        ),
        (
            "mc_pcc_11_1_min",
            f'/ip/firewall/mangle/add {common} per-connection-classifier="both-addresses-and-ports:11/1" comment="{PREFIX}mc_pcc_11_1_min"',
        ),
        (
            "mc_pcc_11_2_min",
            f'/ip/firewall/mangle/add {common} per-connection-classifier="both-addresses-and-ports:11/2" comment="{PREFIX}mc_pcc_11_2_min"',
        ),
        (
            "mc_second_mark_11_1",
            f'/ip/firewall/mangle/add chain=prerouting action=mark-connection new-connection-mark=diag-second passthrough=yes per-connection-classifier="both-addresses-and-ports:11/1" comment="{PREFIX}mc_second_mark_11_1"',
        ),
        (
            "mc_11_1_state",
            f'/ip/firewall/mangle/add {common} connection-state=new per-connection-classifier="both-addresses-and-ports:11/1" comment="{PREFIX}mc_11_1_state"',
        ),
        (
            "mc_11_1_state_nomark",
            f'/ip/firewall/mangle/add {common} connection-state=new connection-mark=no-mark per-connection-classifier="both-addresses-and-ports:11/1" comment="{PREFIX}mc_11_1_state_nomark"',
        ),
        (
            "mc_11_1_state_nomark_dst",
            f'/ip/firewall/mangle/add {common} connection-state=new connection-mark=no-mark dst-address-type=!local per-connection-classifier="both-addresses-and-ports:11/1" comment="{PREFIX}mc_11_1_state_nomark_dst"',
        ),
        (
            "mc_11_1_full",
            f'/ip/firewall/mangle/add {common} connection-state=new connection-mark=no-mark dst-address-type=!local in-interface-list="routercfg-CORE" per-connection-classifier="both-addresses-and-ports:11/1" comment="{PREFIX}mc_11_1_full"',
        ),
        (
            "routing_mark_table_only",
            f'/ip/firewall/mangle/add chain=prerouting action=mark-routing new-routing-mark="to-lab-wan10g" passthrough=no comment="{PREFIX}routing_mark_table_only"',
        ),
        (
            "routing_mark_connection",
            f'/ip/firewall/mangle/add chain=prerouting action=mark-routing connection-mark=diag-common new-routing-mark="to-lab-wan10g" passthrough=no comment="{PREFIX}routing_mark_connection"',
        ),
        (
            "routing_mark_full",
            f'/ip/firewall/mangle/add chain=prerouting action=mark-routing connection-mark=diag-common dst-address-type=!local in-interface-list="routercfg-CORE" new-routing-mark="to-lab-wan10g" passthrough=no comment="{PREFIX}routing_mark_full"',
        ),
    )


def diagnose(*, admin_url: str, output: Path) -> dict[str, Any]:
    admin = base.LoopbackCHRAdmin(admin_url)
    platform = admin.assert_disposable_chr()
    _delete_diagnostics(admin)
    for name in TEMP_FILES:
        base._delete_file_if_present(admin, name)

    before = [
        _summary(row)
        for row in _mangle_rows(admin)
        if str(row.get("comment") or "").startswith("routercfg:managed:pcc-")
    ]
    tables = _routing_tables(admin)
    variants = _diagnostic_commands()
    script = "\n".join(command for _name, command in variants) + "\n"

    created: list[dict[str, Any]] = []
    import_result: dict[str, Any] | None = None
    try:
        chunked._create_text_file_chunk_verified(admin, SCRIPT_FILE, script)
        import_result = mutation._execute_import(
            admin,
            file_name=SCRIPT_FILE,
            expect_success=True,
        )
        rows = _mangle_rows(admin)
        by_comment = {
            str(row.get("comment") or ""): row
            for row in rows
            if str(row.get("comment") or "").startswith(PREFIX)
        }
        for name, _command in variants:
            comment = PREFIX + name
            row = by_comment.get(comment)
            if row is None:
                raise PccRuntimeDiagnosticError(f"CLI diagnostic rule was not created: {name}")
            item = _summary(row)
            item["variant"] = name
            created.append(item)
    finally:
        _delete_diagnostics(admin)
        for name in TEMP_FILES:
            base._delete_file_if_present(admin, name)
        base._assert_files_absent(admin, TEMP_FILES)

    result = {
        "schema_version": "chr-pcc-runtime-diagnostic/2",
        "ok": True,
        "method": "routeros_cli_import_incremental_matrix",
        "platform": {
            "version": str(platform.get("version") or ""),
            "architecture": str(platform.get("architecture-name") or ""),
            "board_name": str(platform.get("board-name") or ""),
        },
        "routing_tables": tables,
        "managed_before": before,
        "managed_invalid_count": sum(1 for row in before if row["invalid"]),
        "diagnostic_import": import_result,
        "diagnostic_variants": created,
        "diagnostic_invalid_count": sum(1 for row in created if row["invalid"]),
        "temporary_rules_removed": True,
        "temporary_files_removed": True,
        "production_writer_available": False,
        "write_authorized": False,
    }
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return result


def main() -> int:
    parser = argparse.ArgumentParser(description="Diagnose PCC invalid-rule causes on disposable CHR")
    parser.add_argument("--admin-url", default="http://127.0.0.1:9380")
    parser.add_argument("--output", required=True)
    args = parser.parse_args()
    try:
        result = diagnose(admin_url=args.admin_url, output=Path(args.output))
        print(json.dumps(result, indent=2, sort_keys=True))
        return 0
    except (OSError, base.CHRRenderDryRunError, PccRuntimeDiagnosticError) as exc:
        failure = {
            "ok": False,
            "error": str(exc),
            "production_writer_available": False,
            "write_authorized": False,
        }
        Path(args.output).write_text(json.dumps(failure, indent=2, sort_keys=True) + "\n", encoding="utf-8")
        print(json.dumps(failure, indent=2, sort_keys=True))
        return 18


if __name__ == "__main__":
    raise SystemExit(main())
