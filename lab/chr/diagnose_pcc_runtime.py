from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any, Mapping

import verify_render_dry_run as base


class PccRuntimeDiagnosticError(RuntimeError):
    pass


PREFIX = "routercfg:diagnostic:pcc:"


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


def _create(admin: base.LoopbackCHRAdmin, *, name: str, fields: Mapping[str, Any]) -> None:
    payload = dict(fields)
    payload["comment"] = PREFIX + name
    admin.request("PUT", "ip/firewall/mangle", payload)


def _summary(row: Mapping[str, Any]) -> dict[str, Any]:
    return {
        "id": str(row.get(".id") or ""),
        "comment": str(row.get("comment") or ""),
        "action": str(row.get("action") or ""),
        "invalid": _bool(row.get("invalid")),
        "disabled": _bool(row.get("disabled")),
        "connection_mark": str(row.get("connection-mark") or ""),
        "new_connection_mark": str(row.get("new-connection-mark") or ""),
        "new_routing_mark": str(row.get("new-routing-mark") or ""),
        "pcc": str(row.get("per-connection-classifier") or ""),
    }


def diagnose(*, admin_url: str, output: Path) -> dict[str, Any]:
    admin = base.LoopbackCHRAdmin(admin_url)
    platform = admin.assert_disposable_chr()
    _delete_diagnostics(admin)

    before = [
        _summary(row)
        for row in _mangle_rows(admin)
        if str(row.get("comment") or "").startswith("routercfg:managed:pcc-")
    ]

    variants: tuple[tuple[str, dict[str, Any]], ...] = (
        (
            "pcc_passthrough_11_0",
            {
                "chain": "prerouting",
                "action": "passthrough",
                "in-interface-list": "routercfg-CORE",
                "dst-address-type": "!local",
                "per-connection-classifier": "both-addresses-and-ports:11/0",
            },
        ),
        (
            "pcc_passthrough_11_1",
            {
                "chain": "prerouting",
                "action": "passthrough",
                "in-interface-list": "routercfg-CORE",
                "dst-address-type": "!local",
                "per-connection-classifier": "both-addresses-and-ports:11/1",
            },
        ),
        (
            "pcc_passthrough_11_2",
            {
                "chain": "prerouting",
                "action": "passthrough",
                "in-interface-list": "routercfg-CORE",
                "dst-address-type": "!local",
                "per-connection-classifier": "both-addresses-and-ports:11/2",
            },
        ),
        (
            "mark_connection_plain_w10",
            {
                "chain": "prerouting",
                "action": "mark-connection",
                "in-interface-list": "routercfg-CORE",
                "new-connection-mark": "diag-w10",
                "passthrough": "yes",
            },
        ),
        (
            "mark_connection_pcc_w1",
            {
                "chain": "prerouting",
                "action": "mark-connection",
                "in-interface-list": "routercfg-CORE",
                "dst-address-type": "!local",
                "connection-state": "new",
                "connection-mark": "no-mark",
                "new-connection-mark": "diag-w1",
                "per-connection-classifier": "both-addresses-and-ports:11/1",
                "passthrough": "yes",
            },
        ),
        (
            "mark_connection_pcc_w10_again",
            {
                "chain": "prerouting",
                "action": "mark-connection",
                "in-interface-list": "routercfg-CORE",
                "dst-address-type": "!local",
                "connection-state": "new",
                "connection-mark": "no-mark",
                "new-connection-mark": "diag-w10",
                "per-connection-classifier": "both-addresses-and-ports:11/2",
                "passthrough": "yes",
            },
        ),
        (
            "mark_routing_w10",
            {
                "chain": "prerouting",
                "action": "mark-routing",
                "in-interface-list": "routercfg-CORE",
                "dst-address-type": "!local",
                "connection-mark": "diag-w10",
                "new-routing-mark": "to-lab-wan10g",
                "passthrough": "no",
            },
        ),
    )

    created: list[dict[str, Any]] = []
    try:
        for name, fields in variants:
            _create(admin, name=name, fields=fields)
        rows = _mangle_rows(admin)
        by_comment = {
            str(row.get("comment") or ""): row
            for row in rows
            if str(row.get("comment") or "").startswith(PREFIX)
        }
        for name, _fields in variants:
            comment = PREFIX + name
            row = by_comment.get(comment)
            if row is None:
                raise PccRuntimeDiagnosticError(f"diagnostic rule was not created: {name}")
            created.append(_summary(row))
    finally:
        _delete_diagnostics(admin)

    result = {
        "schema_version": "chr-pcc-runtime-diagnostic/1",
        "ok": True,
        "platform": {
            "version": str(platform.get("version") or ""),
            "architecture": str(platform.get("architecture-name") or ""),
            "board_name": str(platform.get("board-name") or ""),
        },
        "managed_before": before,
        "managed_invalid_count": sum(1 for row in before if row["invalid"]),
        "diagnostic_variants": created,
        "diagnostic_invalid_count": sum(1 for row in created if row["invalid"]),
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
