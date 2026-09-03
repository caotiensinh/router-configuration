from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any, Mapping

import verify_render_dry_run as base


TABLE_NAME = "routercfg-pbr-dp-table"
RULE_COMMENT = "routercfg:managed:pbr:route-selection-data-plane"
MAIN_ROUTE_COMMENT = "routercfg:lab:pbr-dp:route:main"
PBR_ROUTE_COMMENT = "routercfg:lab:pbr-dp:route:pbr"


def _records(admin: base.LoopbackCHRAdmin, path: str) -> list[Mapping[str, Any]]:
    _, payload = admin.request("GET", path)
    return list(base._rows(payload))


def _select(rows: list[Mapping[str, Any]], *, key: str, value: str) -> list[Mapping[str, Any]]:
    return [row for row in rows if str(row.get(key) or "") == value]


def _safe_row(row: Mapping[str, Any]) -> dict[str, Any]:
    fields = (
        ".id",
        "dst-address",
        "gateway",
        "immediate-gw",
        "routing-table",
        "distance",
        "active",
        "dynamic",
        "invalid",
        "disabled",
        "unreachable",
        "comment",
    )
    return {field: row[field] for field in fields if field in row}


def _table_row(row: Mapping[str, Any]) -> dict[str, Any]:
    fields = (".id", "name", "fib", "invalid", "disabled")
    return {field: row[field] for field in fields if field in row}


def _rule_row(row: Mapping[str, Any]) -> dict[str, Any]:
    fields = (
        ".id",
        "src-address",
        "dst-address",
        "action",
        "table",
        "invalid",
        "disabled",
        "comment",
    )
    return {field: row[field] for field in fields if field in row}


def _truth(value: Any) -> bool:
    return base._is_true(value)


def diagnose(*, admin_url: str, workflow_sha: str) -> dict[str, Any]:
    admin = base.LoopbackCHRAdmin(admin_url)
    platform = admin.assert_disposable_chr()

    routes = _records(admin, "ip/route")
    tables = _records(admin, "routing/table")
    rules = _records(admin, "routing/rule")

    main_rows = _select(routes, key="comment", value=MAIN_ROUTE_COMMENT)
    pbr_rows = _select(routes, key="comment", value=PBR_ROUTE_COMMENT)
    table_rows = _select(tables, key="name", value=TABLE_NAME)
    rule_rows = _select(rules, key="comment", value=RULE_COMMENT)

    if len(main_rows) != 1:
        raise RuntimeError(f"expected one MAIN lab route, observed {len(main_rows)}")
    if len(pbr_rows) != 1:
        raise RuntimeError(f"expected one PBR lab route, observed {len(pbr_rows)}")
    if len(table_rows) != 1:
        raise RuntimeError(f"expected one custom routing table, observed {len(table_rows)}")
    if len(rule_rows) != 1:
        raise RuntimeError(f"expected one production-rendered PBR rule, observed {len(rule_rows)}")

    main = main_rows[0]
    pbr = pbr_rows[0]
    table = table_rows[0]
    rule = rule_rows[0]

    main_active = _truth(main.get("active"))
    pbr_active = _truth(pbr.get("active"))
    pbr_resolved = bool(str(pbr.get("immediate-gw") or "").strip())
    table_fib = _truth(table.get("fib"))
    rule_valid = not _truth(rule.get("invalid")) and not _truth(rule.get("disabled"))

    fib_ready = pbr_active and pbr_resolved and table_fib and rule_valid
    reason = "ready"
    if not table_fib:
        reason = "custom_table_not_fib"
    elif not pbr_active:
        reason = "custom_route_inactive"
    elif not pbr_resolved:
        reason = "custom_route_gateway_unresolved"
    elif not rule_valid:
        reason = "production_rule_invalid_or_disabled"

    return {
        "ok": True,
        "acceptance": "DIAGNOSTIC",
        "workflow_sha": workflow_sha,
        "platform": {
            "version": str(platform.get("version") or ""),
            "architecture": str(platform.get("architecture-name") or ""),
            "board_name": str(platform.get("board-name") or ""),
        },
        "fib_ready_for_measured_flow": fib_ready,
        "diagnostic_reason": reason,
        "main_route_active": main_active,
        "custom_route_active": pbr_active,
        "custom_route_gateway_resolved": pbr_resolved,
        "custom_table_fib": table_fib,
        "production_rule_valid": rule_valid,
        "main_route": _safe_row(main),
        "custom_route": _safe_row(pbr),
        "custom_table": _table_row(table),
        "production_rule": _rule_row(rule),
        "production_writer_available": False,
        "transport_exposed_to_product": False,
        "write_authorized": False,
        "physical_router_targeted": False,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description="Capture RouterOS PBR FIB state before measured route-selection traffic")
    parser.add_argument("--admin-url", default="http://127.0.0.1:9980")
    parser.add_argument("--workflow-sha", required=True)
    parser.add_argument("--output", required=True)
    args = parser.parse_args()

    output = Path(args.output)
    output.parent.mkdir(parents=True, exist_ok=True)
    try:
        result = diagnose(admin_url=args.admin_url, workflow_sha=args.workflow_sha)
        rc = 0
    except Exception as exc:
        result = {
            "ok": False,
            "acceptance": "DIAGNOSTIC_FAIL",
            "workflow_sha": args.workflow_sha,
            "error": str(exc),
            "fib_ready_for_measured_flow": False,
            "production_writer_available": False,
            "transport_exposed_to_product": False,
            "write_authorized": False,
            "physical_router_targeted": False,
        }
        rc = 1
    output.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(json.dumps(result, indent=2, sort_keys=True))
    return rc


if __name__ == "__main__":
    raise SystemExit(main())
