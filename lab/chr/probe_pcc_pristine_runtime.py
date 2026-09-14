from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any, Mapping

import verify_mutation_rollback as mutation
import verify_render_dry_run as base
import verify_render_dry_run_chunked as chunked


class PCCPristineProbeError(RuntimeError):
    pass


PREFIX = "routercfg:diagnostic:pcc-pristine:"
SCRIPT_FILE = "routercfg-pcc-pristine-probe.rsc"
VERDICT_FILE = "routercfg-pcc-pristine-probe-verdict.txt"
TEMP_FILES = (SCRIPT_FILE, VERDICT_FILE)


def _rows(admin: base.LoopbackCHRAdmin) -> list[dict[str, Any]]:
    _, payload = admin.request("GET", "ip/firewall/mangle")
    return [dict(row) for row in base._rows(payload)]


def _delete_probe_rows(admin: base.LoopbackCHRAdmin) -> None:
    for row in _rows(admin):
        if not str(row.get("comment") or "").startswith(PREFIX):
            continue
        row_id = str(row.get(".id") or "").strip()
        if row_id:
            admin.request("DELETE", f"ip/firewall/mangle/{row_id}")


def _summary(row: Mapping[str, Any]) -> dict[str, Any]:
    return {
        "comment": str(row.get("comment") or ""),
        "action": str(row.get("action") or ""),
        "invalid": base._is_true(row.get("invalid")),
        "disabled": base._is_true(row.get("disabled")),
        "new_connection_mark": str(row.get("new-connection-mark") or ""),
        "pcc": str(row.get("per-connection-classifier") or ""),
    }


def _import_one(admin: base.LoopbackCHRAdmin, command: str) -> None:
    chunked._create_text_file_chunk_verified(admin, SCRIPT_FILE, command + "\n")
    mutation._execute_import(admin, file_name=SCRIPT_FILE, expect_success=True)


def _find_probe_rows(admin: base.LoopbackCHRAdmin) -> list[dict[str, Any]]:
    result = [
        _summary(row)
        for row in _rows(admin)
        if str(row.get("comment") or "").startswith(PREFIX)
    ]
    result.sort(key=lambda row: row["comment"])
    return result


def _isolated_case(
    admin: base.LoopbackCHRAdmin,
    *,
    name: str,
    command: str,
) -> dict[str, Any]:
    _delete_probe_rows(admin)
    _import_one(admin, command)
    observed = _find_probe_rows(admin)
    if len(observed) != 1:
        raise PCCPristineProbeError(
            f"isolated probe {name!r} expected one rule, observed {len(observed)}"
        )
    result = {"name": name, "rows": observed}
    _delete_probe_rows(admin)
    return result


def _cumulative_case(
    admin: base.LoopbackCHRAdmin,
    *,
    name: str,
    commands: tuple[str, ...],
) -> dict[str, Any]:
    _delete_probe_rows(admin)
    for command in commands:
        _import_one(admin, command)
    observed = _find_probe_rows(admin)
    if len(observed) != len(commands):
        raise PCCPristineProbeError(
            f"cumulative probe {name!r} expected {len(commands)} rules, observed {len(observed)}"
        )
    result = {"name": name, "rows": observed}
    _delete_probe_rows(admin)
    return result


def probe(*, admin_url: str, output: Path) -> dict[str, Any]:
    admin = base.LoopbackCHRAdmin(admin_url)
    platform = admin.assert_disposable_chr()
    for temp in TEMP_FILES:
        base._delete_file_if_present(admin, temp)
    _delete_probe_rows(admin)

    pcc0 = (
        f'/ip/firewall/mangle/add chain=prerouting action=accept '
        f'per-connection-classifier="both-addresses-and-ports:2/0" '
        f'comment="{PREFIX}accept-pcc-2-0"'
    )
    pcc1 = (
        f'/ip/firewall/mangle/add chain=prerouting action=accept '
        f'per-connection-classifier="both-addresses-and-ports:2/1" '
        f'comment="{PREFIX}accept-pcc-2-1"'
    )
    mark_a = (
        f'/ip/firewall/mangle/add chain=prerouting action=mark-connection '
        f'new-connection-mark="routercfg-diag-a" passthrough=yes '
        f'comment="{PREFIX}mark-a"'
    )
    mark_b = (
        f'/ip/firewall/mangle/add chain=prerouting action=mark-connection '
        f'new-connection-mark="routercfg-diag-b" passthrough=yes '
        f'comment="{PREFIX}mark-b"'
    )

    cases: list[dict[str, Any]] = []
    try:
        cases.append(_isolated_case(admin, name="pcc_2_0_isolated", command=pcc0))
        cases.append(_isolated_case(admin, name="pcc_2_1_isolated", command=pcc1))
        cases.append(
            _cumulative_case(
                admin,
                name="pcc_2_0_then_2_1",
                commands=(pcc0, pcc1),
            )
        )
        cases.append(_isolated_case(admin, name="mark_a_isolated", command=mark_a))
        cases.append(
            _cumulative_case(
                admin,
                name="mark_a_then_mark_b",
                commands=(mark_a, mark_b),
            )
        )
    finally:
        _delete_probe_rows(admin)
        for temp in TEMP_FILES:
            base._delete_file_if_present(admin, temp)
        base._assert_files_absent(admin, TEMP_FILES)

    all_rows = [row for case in cases for row in case["rows"]]
    result = {
        "schema_version": "chr-pcc-pristine-runtime-probe/1",
        "ok": True,
        "scope": "disposable_chr_pristine_runtime_diagnostic_only",
        "platform": {
            "version": str(platform.get("version") or ""),
            "architecture": str(platform.get("architecture-name") or ""),
            "board_name": str(platform.get("board-name") or ""),
        },
        "cases": cases,
        "invalid_observed": any(bool(row["invalid"]) for row in all_rows),
        "probe_rules_removed": True,
        "temporary_files_removed": True,
        "production_writer_available": False,
        "write_authorized": False,
    }
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return result


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Probe PCC and connection-mark validity on pristine disposable CHR"
    )
    parser.add_argument("--admin-url", default="http://127.0.0.1:9380")
    parser.add_argument("--output", required=True)
    args = parser.parse_args()
    try:
        result = probe(admin_url=args.admin_url, output=Path(args.output))
        print(json.dumps(result, indent=2, sort_keys=True))
        return 0
    except (OSError, base.CHRRenderDryRunError, PCCPristineProbeError) as exc:
        failure = {
            "schema_version": "chr-pcc-pristine-runtime-probe/1",
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
