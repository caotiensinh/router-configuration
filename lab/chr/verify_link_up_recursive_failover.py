from __future__ import annotations

import argparse
import json
import time
from pathlib import Path
from typing import Any, Mapping

import verify_mutation_rollback as mutation
import verify_packet_flow_behavior as flow
import verify_render_dry_run as base
import verify_render_dry_run_chunked as chunked
from router_configuration.routeros_renderer import RouterOSSafeSubsetRenderer


class CHRLinkUpRecursiveError(RuntimeError):
    pass


APPLY_FILE = "routercfg-linkup-recursive-apply.rsc"
VERDICT_FILE = "routercfg-linkup-recursive-verdict.txt"
TEMP_FILES = (APPLY_FILE, VERDICT_FILE)


def _commands() -> list[Mapping[str, Any]]:
    plan = RouterOSSafeSubsetRenderer().render(flow._build_ir()).as_dict()
    commands = plan.get("commands", [])
    if not isinstance(commands, list) or len(commands) != 17:
        raise CHRLinkUpRecursiveError(
            f"recursive lab requires exactly 17 base commands; observed "
            f"{len(commands) if isinstance(commands, list) else 'non-list'}"
        )
    return commands


def _script() -> str:
    prelude = [
        '/ip/firewall/filter/remove [find]',
        '/ip/firewall/nat/remove [find]',
        '/ip/firewall/mangle/remove [find]',
        '/interface/bridge/port/remove [find where interface=ether2]',
        '/interface/bridge/port/remove [find where interface=ether3]',
        '/interface/bridge/port/remove [find where interface=ether4]',
        '/ip/address/remove [find where interface=ether2]',
        '/ip/address/remove [find where interface=ether3]',
        '/ip/address/remove [find where interface=ether4]',
        '/ip/dhcp-client/set [find where interface=ether1] default-route-distance=250',
        '/routing/settings/set check-gateway-ping-count=2 check-gateway-ping-interval=500ms check-gateway-ping-timeout=200ms',
        '/ip/address/add address="10.10.10.1/24" interface="ether4" comment="routercfg:lab:core-address"',
    ]
    return "\n".join([*prelude, *(str(item["command"]) for item in _commands())]) + "\n"


def _active_route_ids(admin: base.LoopbackCHRAdmin) -> set[str]:
    """Ask RouterOS itself which routes are active instead of inferring flag absence."""
    _, payload = admin.request("GET", "ip/route?active=true")
    return {
        route_id
        for row in base._rows(payload)
        if (route_id := str(row.get(".id") or ""))
    }


def _managed_defaults(admin: base.LoopbackCHRAdmin) -> list[dict[str, Any]]:
    _, payload = admin.request("GET", "ip/route")
    active_ids = _active_route_ids(admin)
    rows = []
    for row in base._rows(payload):
        comment = str(row.get("comment") or "")
        if not comment.startswith("routercfg:managed:default:"):
            continue
        route_id = str(row.get(".id") or "")
        rows.append(
            {
                "route_id": route_id,
                "comment": comment,
                "active": bool(route_id) and route_id in active_ids,
                "inactive": base._is_true(row.get("inactive")),
                "distance": str(row.get("distance") or ""),
                "gateway": str(row.get("gateway") or ""),
                "immediate_gateway": str(row.get("immediate-gw") or ""),
                "routing_table": str(row.get("routing-table") or ""),
            }
        )
    rows.sort(key=lambda item: item["comment"])
    return rows


def _management_dhcp_defaults(admin: base.LoopbackCHRAdmin) -> list[dict[str, Any]]:
    _, payload = admin.request("GET", "ip/route")
    rows: list[dict[str, Any]] = []
    for row in base._rows(payload):
        if not base._is_true(row.get("dhcp")):
            continue
        if str(row.get("dst-address") or "") != "0.0.0.0/0":
            continue
        rows.append(
            {
                "route_id": str(row.get(".id") or ""),
                "distance": str(row.get("distance") or ""),
                "gateway": str(row.get("gateway") or ""),
                "immediate_gateway": str(row.get("immediate-gw") or ""),
                "active": base._is_true(row.get("active")),
                "dhcp": True,
            }
        )
    return rows


def _route_condition(rows: list[dict[str, Any]], expected: str) -> bool:
    wan10 = [row for row in rows if ":lab-wan10g:" in row["comment"]]
    wan1 = [row for row in rows if ":lab-wan1g:" in row["comment"]]
    if len(wan10) != 2 or len(wan1) != 2:
        return False
    if expected in {"normal", "recovered"}:
        return any(row["active"] for row in wan10) and not any(
            row["active"] for row in wan1
        )
    if expected == "wan10_failed":
        return not any(row["active"] for row in wan10) and any(
            row["active"] for row in wan1
        )
    raise CHRLinkUpRecursiveError(f"unsupported route expectation: {expected}")


def _endpoint_snapshot(admin: base.LoopbackCHRAdmin, path: str) -> dict[str, Any]:
    try:
        status, payload = admin.request("GET", path)
    except Exception as exc:  # diagnostic capture must not hide the primary timeout
        return {
            "ok": False,
            "endpoint": path,
            "error": f"{type(exc).__name__}: {exc}",
        }
    return {
        "ok": 200 <= int(status) < 300,
        "endpoint": path,
        "http_status": int(status),
        "payload": payload,
    }


def _write_timeout_diagnostic(
    *,
    admin: base.LoopbackCHRAdmin,
    output: Path,
    expected: str,
    timeout_seconds: float,
    attempts: int,
    rows: list[dict[str, Any]],
) -> Path:
    diagnostic_path = output.with_name(f"{output.stem}-diagnostic.json")
    payload = {
        "schema_version": "chr-link-up-recursive-timeout-diagnostic/2",
        "ok": False,
        "expected": expected,
        "timeout_seconds": timeout_seconds,
        "attempts": attempts,
        "managed_defaults": rows,
        "routing_settings": _endpoint_snapshot(admin, "routing/settings"),
        "ip_routes": _endpoint_snapshot(admin, "ip/route"),
        "active_ip_routes": _endpoint_snapshot(admin, "ip/route?active=true"),
        "routing_routes": _endpoint_snapshot(admin, "routing/route"),
        "routing_nexthops": _endpoint_snapshot(admin, "routing/nexthop"),
        "production_writer_available": False,
        "write_authorized": False,
    }
    diagnostic_path.write_text(
        json.dumps(payload, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    return diagnostic_path


def prepare(*, admin_url: str, output: Path) -> dict[str, Any]:
    admin = base.LoopbackCHRAdmin(admin_url)
    platform = admin.assert_disposable_chr()
    for name in TEMP_FILES:
        base._delete_file_if_present(admin, name)
    script = _script()
    try:
        chunked._create_text_file_chunk_verified(admin, APPLY_FILE, script)
        chunked._create_text_file_chunk_verified(admin, VERDICT_FILE, "PENDING")
        dry_run = base._execute_import_dry_run(
            admin, file_name=APPLY_FILE, verdict_name=VERDICT_FILE, expect_success=True
        )
        apply_result = mutation._execute_import(
            admin, file_name=APPLY_FILE, expect_success=True
        )
    finally:
        for name in TEMP_FILES:
            base._delete_file_if_present(admin, name)
        base._assert_files_absent(admin, TEMP_FILES)

    rows = _managed_defaults(admin)
    if len(rows) != 4:
        raise CHRLinkUpRecursiveError(
            f"expected four managed main-table recursive defaults, observed {len(rows)}"
        )
    management_defaults = _management_dhcp_defaults(admin)
    management_distances = sorted(
        {str(row.get("distance") or "") for row in management_defaults}
    )
    if not management_defaults or management_distances != ["250"]:
        raise CHRLinkUpRecursiveError(
            "disposable CHR management DHCP default route is not isolated at distance 250; "
            f"observed={management_distances}"
        )
    result = {
        "schema_version": "chr-link-up-recursive-prepare/2",
        "ok": True,
        "platform": {
            "version": str(platform.get("version") or ""),
            "architecture": str(platform.get("architecture-name") or ""),
            "board_name": str(platform.get("board-name") or ""),
        },
        "generated_command_count": 17,
        "managed_default_count": len(rows),
        "management_dhcp_default_count": len(management_defaults),
        "management_dhcp_default_distances": management_distances,
        "dry_run": dry_run,
        "apply": apply_result,
        "production_writer_available": False,
        "write_authorized": False,
    }
    output.write_text(
        json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    return result


def wait_routes(
    *, admin_url: str, expected: str, timeout_seconds: float, output: Path
) -> dict[str, Any]:
    admin = base.LoopbackCHRAdmin(admin_url)
    admin.assert_disposable_chr()
    deadline = time.monotonic() + timeout_seconds
    attempts = 0
    rows: list[dict[str, Any]] = []
    while True:
        attempts += 1
        rows = _managed_defaults(admin)
        if _route_condition(rows, expected):
            break
        if time.monotonic() >= deadline:
            diagnostic_path = _write_timeout_diagnostic(
                admin=admin,
                output=output,
                expected=expected,
                timeout_seconds=timeout_seconds,
                attempts=attempts,
                rows=rows,
            )
            raise CHRLinkUpRecursiveError(
                f"main-table route state did not reach {expected!r} within {timeout_seconds}s; "
                f"diagnostic={diagnostic_path.name}"
            )
        time.sleep(0.25)
    result = {
        "schema_version": "chr-link-up-recursive-route-state/2",
        "ok": True,
        "expected": expected,
        "attempts": attempts,
        "routes": rows,
    }
    output.write_text(
        json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    return result


def _metrics(path: Path) -> dict[str, int]:
    payload = json.loads(path.read_text(encoding="utf-8"))
    tags = payload.get("tags", {}) if isinstance(payload, Mapping) else {}
    return {
        "requested": int(payload.get("requested_flows") or 0),
        "successful": int(payload.get("successful_flows") or 0),
        "wan10": int(tags.get("WAN10") or 0) if isinstance(tags, Mapping) else 0,
        "wan1": int(tags.get("WAN1") or 0) if isinstance(tags, Mapping) else 0,
    }


def evaluate(
    *,
    normal: Path,
    failover: Path,
    recovery: Path,
    failed_routes: Path,
    recovered_routes: Path,
    output: Path,
) -> dict[str, Any]:
    phases = {
        "normal": _metrics(normal),
        "failover": _metrics(failover),
        "recovery": _metrics(recovery),
    }
    errors: list[str] = []
    for label in ("normal", "recovery"):
        item = phases[label]
        if item["requested"] <= 0 or item["successful"] < int(
            item["requested"] * 0.97
        ):
            errors.append(f"{label}: successful flow ratio below 97%")
        if item["wan10"] != item["successful"] or item["wan1"] != 0:
            errors.append(f"{label}: flows did not remain on preferred WAN10")
    failed = phases["failover"]
    if failed["requested"] <= 0 or failed["successful"] < int(
        failed["requested"] * 0.95
    ):
        errors.append("failover: successful flow ratio below 95%")
    if failed["wan1"] != failed["successful"] or failed["wan10"] != 0:
        errors.append("failover: flows did not move completely to WAN1")

    failed_route_payload = json.loads(failed_routes.read_text(encoding="utf-8"))
    recovered_route_payload = json.loads(recovered_routes.read_text(encoding="utf-8"))
    if (
        failed_route_payload.get("expected") != "wan10_failed"
        or failed_route_payload.get("ok") is not True
    ):
        errors.append("failover route-state evidence missing or invalid")
    if (
        recovered_route_payload.get("expected") != "recovered"
        or recovered_route_payload.get("ok") is not True
    ):
        errors.append("recovery route-state evidence missing or invalid")

    result = {
        "schema_version": "chr-internet-down-link-up-packet-flow/1",
        "ok": not errors,
        "acceptance": "PASS" if not errors else "FAIL",
        "errors": errors,
        "phases": phases,
        "route_failure_observed": failed_route_payload.get("ok") is True,
        "route_recovery_observed": recovered_route_payload.get("ok") is True,
        "production_writer_available": False,
        "write_authorized": False,
    }
    output.write_text(
        json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    if errors:
        raise CHRLinkUpRecursiveError("; ".join(errors))
    return result


def main() -> int:
    parser = argparse.ArgumentParser()
    sub = parser.add_subparsers(dest="command", required=True)
    p = sub.add_parser("prepare")
    p.add_argument("--admin-url", default="http://127.0.0.1:9380")
    p.add_argument("--output", required=True)
    w = sub.add_parser("wait-routes")
    w.add_argument("--admin-url", default="http://127.0.0.1:9380")
    w.add_argument(
        "--expected", choices=("normal", "wan10_failed", "recovered"), required=True
    )
    w.add_argument("--timeout-seconds", type=float, default=15.0)
    w.add_argument("--output", required=True)
    e = sub.add_parser("evaluate")
    for name in (
        "normal",
        "failover",
        "recovery",
        "failed-routes",
        "recovered-routes",
        "output",
    ):
        e.add_argument(f"--{name}", required=True)
    args = parser.parse_args()
    try:
        if args.command == "prepare":
            result = prepare(admin_url=args.admin_url, output=Path(args.output))
        elif args.command == "wait-routes":
            result = wait_routes(
                admin_url=args.admin_url,
                expected=args.expected,
                timeout_seconds=args.timeout_seconds,
                output=Path(args.output),
            )
        else:
            result = evaluate(
                normal=Path(args.normal),
                failover=Path(args.failover),
                recovery=Path(args.recovery),
                failed_routes=Path(args.failed_routes),
                recovered_routes=Path(args.recovered_routes),
                output=Path(args.output),
            )
        print(json.dumps(result, indent=2, sort_keys=True))
        return 0
    except (
        OSError,
        ValueError,
        base.CHRRenderDryRunError,
        CHRLinkUpRecursiveError,
    ) as exc:
        failure = {
            "ok": False,
            "acceptance": "FAIL",
            "error": str(exc),
            "production_writer_available": False,
            "write_authorized": False,
        }
        output_value = getattr(args, "output", None)
        if output_value:
            Path(output_value).write_text(
                json.dumps(failure, indent=2, sort_keys=True) + "\n",
                encoding="utf-8",
            )
        print(json.dumps(failure, indent=2, sort_keys=True))
        return 17


if __name__ == "__main__":
    raise SystemExit(main())
