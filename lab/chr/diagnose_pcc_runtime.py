from __future__ import annotations

import argparse
import json
import time
from pathlib import Path
from typing import Any, Mapping

import verify_mutation_rollback as mutation
import verify_render_dry_run as base
import verify_render_dry_run_chunked as chunked


class PccRuntimeDiagnosticError(RuntimeError):
    pass


PREFIX = "routercfg:diagnostic:pcc:"
MANAGED_PREFIX = "routercfg:managed:pcc-"
SCRIPT_FILE = "routercfg-pcc-runtime-diagnostic.rsc"
VERDICT_FILE = "routercfg-pcc-runtime-diagnostic-verdict.txt"
TEMP_FILES = (SCRIPT_FILE, VERDICT_FILE)
EXPECTED_MANAGED_RULES = 13
READBACK_SETTLE_SECONDS = 3.0
READBACK_INTERVAL_SECONDS = 0.10
REQUIRED_STABLE_VALID_READS = 2


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


def _managed_rows(admin: base.LoopbackCHRAdmin) -> list[dict[str, Any]]:
    return [
        _summary(row)
        for row in _mangle_rows(admin)
        if str(row.get("comment") or "").startswith(MANAGED_PREFIX)
    ]


def _wait_for_managed_convergence(
    admin: base.LoopbackCHRAdmin,
    *,
    timeout_seconds: float = READBACK_SETTLE_SECONDS,
    interval_seconds: float = READBACK_INTERVAL_SECONDS,
) -> tuple[list[dict[str, Any]], list[dict[str, Any]], bool]:
    """Observe RouterOS runtime validation until two consecutive valid reads.

    RouterOS may expose freshly imported mangle rules before its runtime
    registration flags have converged.  This path is deliberately read-only:
    it never adds, enables, disables or rewrites a rule.  Acceptance requires
    the full expected managed set to be valid on two consecutive snapshots;
    persistent invalid state still fails closed.
    """

    deadline = time.monotonic() + timeout_seconds
    snapshots: list[dict[str, Any]] = []
    latest: list[dict[str, Any]] = []
    stable_valid_reads = 0
    attempt = 0

    while True:
        attempt += 1
        latest = _managed_rows(admin)
        invalid = [row for row in latest if row["invalid"]]
        snapshot = {
            "attempt": attempt,
            "rule_count": len(latest),
            "invalid_count": len(invalid),
            "invalid_comments": [row["comment"] for row in invalid],
        }
        snapshots.append(snapshot)

        complete_and_valid = len(latest) == EXPECTED_MANAGED_RULES and not invalid
        stable_valid_reads = stable_valid_reads + 1 if complete_and_valid else 0
        if stable_valid_reads >= REQUIRED_STABLE_VALID_READS:
            return latest, snapshots, True

        if time.monotonic() >= deadline:
            return latest, snapshots, False
        time.sleep(interval_seconds)


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
    """Deep CLI variants used only when --deep is explicitly requested."""

    common = "chain=prerouting action=mark-connection new-connection-mark=diag-common passthrough=yes"
    existing = "chain=prerouting action=mark-connection new-connection-mark=routercfg-pcc-lab-wan10g passthrough=yes"
    return (
        ("mc_existing_plain", f'/ip/firewall/mangle/add {existing} comment="{PREFIX}mc_existing_plain"'),
        ("mc_existing_pcc_2_0", f'/ip/firewall/mangle/add {existing} per-connection-classifier="both-addresses-and-ports:2/0" comment="{PREFIX}mc_existing_pcc_2_0"'),
        ("mc_existing_pcc_2_1", f'/ip/firewall/mangle/add {existing} per-connection-classifier="both-addresses-and-ports:2/1" comment="{PREFIX}mc_existing_pcc_2_1"'),
        ("mc_existing_pcc_3_1", f'/ip/firewall/mangle/add {existing} per-connection-classifier="both-addresses-and-ports:3/1" comment="{PREFIX}mc_existing_pcc_3_1"'),
        ("mc_existing_pcc_10_1", f'/ip/firewall/mangle/add {existing} per-connection-classifier="both-addresses-and-ports:10/1" comment="{PREFIX}mc_existing_pcc_10_1"'),
        ("mc_existing_pcc_11_1", f'/ip/firewall/mangle/add {existing} per-connection-classifier="both-addresses-and-ports:11/1" comment="{PREFIX}mc_existing_pcc_11_1"'),
        ("mc_existing_pcc_11_10", f'/ip/firewall/mangle/add {existing} per-connection-classifier="both-addresses-and-ports:11/10" comment="{PREFIX}mc_existing_pcc_11_10"'),
        ("mc_pcc_11_0_min", f'/ip/firewall/mangle/add {common} per-connection-classifier="both-addresses-and-ports:11/0" comment="{PREFIX}mc_pcc_11_0_min"'),
        ("mc_pcc_11_1_min", f'/ip/firewall/mangle/add {common} per-connection-classifier="both-addresses-and-ports:11/1" comment="{PREFIX}mc_pcc_11_1_min"'),
        ("mc_second_mark_11_1", f'/ip/firewall/mangle/add chain=prerouting action=mark-connection new-connection-mark=diag-second passthrough=yes per-connection-classifier="both-addresses-and-ports:11/1" comment="{PREFIX}mc_second_mark_11_1"'),
        ("mc_11_1_state", f'/ip/firewall/mangle/add {common} connection-state=new per-connection-classifier="both-addresses-and-ports:11/1" comment="{PREFIX}mc_11_1_state"'),
        ("mc_11_1_state_nomark", f'/ip/firewall/mangle/add {common} connection-state=new connection-mark=no-mark per-connection-classifier="both-addresses-and-ports:11/1" comment="{PREFIX}mc_11_1_state_nomark"'),
        ("mc_11_1_state_nomark_dst", f'/ip/firewall/mangle/add {common} connection-state=new connection-mark=no-mark dst-address-type=!local per-connection-classifier="both-addresses-and-ports:11/1" comment="{PREFIX}mc_11_1_state_nomark_dst"'),
        ("mc_11_1_full", f'/ip/firewall/mangle/add {common} connection-state=new connection-mark=no-mark dst-address-type=!local in-interface-list="routercfg-CORE" per-connection-classifier="both-addresses-and-ports:11/1" comment="{PREFIX}mc_11_1_full"'),
        ("routing_mark_table_only", f'/ip/firewall/mangle/add chain=prerouting action=mark-routing new-routing-mark="to-lab-wan10g" passthrough=no comment="{PREFIX}routing_mark_table_only"'),
        ("routing_mark_existing_connection", f'/ip/firewall/mangle/add chain=prerouting action=mark-routing connection-mark=routercfg-pcc-lab-wan10g new-routing-mark="to-lab-wan10g" passthrough=no comment="{PREFIX}routing_mark_existing_connection"'),
        ("routing_mark_full_existing", f'/ip/firewall/mangle/add chain=prerouting action=mark-routing connection-mark=routercfg-pcc-lab-wan10g dst-address-type=!local in-interface-list="routercfg-CORE" new-routing-mark="to-lab-wan10g" passthrough=no comment="{PREFIX}routing_mark_full_existing"'),
    )


def _run_deep_matrix(admin: base.LoopbackCHRAdmin) -> tuple[dict[str, Any], list[dict[str, Any]]]:
    """Run the synthetic diagnostic matrix for RCA, never for normal hard acceptance."""

    _delete_diagnostics(admin)
    for name in TEMP_FILES:
        base._delete_file_if_present(admin, name)

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

    if import_result is None:
        raise PccRuntimeDiagnosticError("deep diagnostic import did not produce a result")
    return import_result, created


def diagnose(*, admin_url: str, output: Path, deep: bool = False) -> dict[str, Any]:
    admin = base.LoopbackCHRAdmin(admin_url)
    platform = admin.assert_disposable_chr()

    # RouterOS can expose a freshly imported mangle row before all runtime
    # registration flags have converged.  Observe only: no synthetic mutation
    # is allowed on the hard-acceptance path.  Require two consecutive complete
    # and valid snapshots so a one-read transient cannot become a false PASS.
    managed, convergence, converged = _wait_for_managed_convergence(admin)
    if not managed:
        raise PccRuntimeDiagnosticError("no managed PCC rules were present after apply")

    tables = _routing_tables(admin)
    import_result: dict[str, Any] | None = None
    created: list[dict[str, Any]] = []
    if deep:
        import_result, created = _run_deep_matrix(admin)

    result = {
        "schema_version": "chr-pcc-runtime-diagnostic/5",
        "ok": converged,
        "method": (
            "routeros_cli_import_existing_mark_and_modulus_matrix"
            if deep
            else "managed_rule_runtime_readback_without_synthetic_mutation"
        ),
        "mode": "deep" if deep else "managed_readback",
        "platform": {
            "version": str(platform.get("version") or ""),
            "architecture": str(platform.get("architecture-name") or ""),
            "board_name": str(platform.get("board-name") or ""),
        },
        "routing_tables": tables,
        "managed_before": managed,
        "managed_rule_count": len(managed),
        "managed_invalid_count": sum(1 for row in managed if row["invalid"]),
        "managed_runtime_converged": converged,
        "managed_runtime_convergence": convergence,
        "required_stable_valid_reads": REQUIRED_STABLE_VALID_READS,
        "readback_settle_seconds": READBACK_SETTLE_SECONDS,
        "diagnostic_import": import_result,
        "diagnostic_variants": created,
        "diagnostic_invalid_count": sum(1 for row in created if row["invalid"]),
        "synthetic_mutation_performed": deep,
        "temporary_rules_removed": True,
        "temporary_files_removed": True,
        "production_writer_available": False,
        "write_authorized": False,
    }
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return result


def main() -> int:
    parser = argparse.ArgumentParser(description="Diagnose PCC runtime validity on disposable CHR")
    parser.add_argument("--admin-url", default="http://127.0.0.1:9380")
    parser.add_argument("--output", required=True)
    parser.add_argument(
        "--deep",
        action="store_true",
        help="run the synthetic CLI variant matrix for RCA; default acceptance is readback-only",
    )
    args = parser.parse_args()
    try:
        result = diagnose(admin_url=args.admin_url, output=Path(args.output), deep=args.deep)
        print(json.dumps(result, indent=2, sort_keys=True))
        return 0 if result["ok"] else 18
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
