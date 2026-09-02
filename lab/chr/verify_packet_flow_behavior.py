from __future__ import annotations

import argparse
import json
import time
from pathlib import Path
from typing import Any, Mapping

import verify_mutation_rollback as mutation
import verify_render_dry_run as base
import verify_render_dry_run_chunked as chunked
from router_configuration.routeros_pcc_renderer import render_routeros_pcc
from router_configuration.routeros_renderer import RouterOSSafeSubsetRenderer
from router_configuration.safe_subset_ir import IntentOperation, IntentRisk, SafeSubsetIR


class CHRPacketFlowError(RuntimeError):
    pass


APPLY_FILE = "routercfg-flow-apply.rsc"
VERDICT_FILE = "routercfg-flow-verdict.txt"
TEMP_FILES = (APPLY_FILE, VERDICT_FILE)


def _build_ir() -> dict[str, Any]:
    return SafeSubsetIR(
        device_id="chr-packet-flow-lab",
        operations=(
            IntentOperation(
                operation_id="topology.wan.lab-wan10g",
                feature="topology",
                resource="wan_role",
                attributes={
                    "name": "lab-wan10g",
                    "interface": "ether2",
                    "capacity_mbps": 10000,
                    "addressing": "static",
                    "address": "192.0.2.2/30",
                },
                risk=IntentRisk.MEDIUM,
                requires=("interfaces",),
            ),
            IntentOperation(
                operation_id="topology.wan.lab-wan1g",
                feature="topology",
                resource="wan_role",
                attributes={
                    "name": "lab-wan1g",
                    "interface": "ether3",
                    "capacity_mbps": 1000,
                    "addressing": "static",
                    "address": "198.51.100.2/30",
                },
                risk=IntentRisk.MEDIUM,
                requires=("interfaces",),
            ),
            IntentOperation(
                operation_id="topology.core",
                feature="topology",
                resource="core_uplink_role",
                attributes={"interface": "ether4", "capacity_mbps": 10000},
                risk=IntentRisk.MEDIUM,
                requires=("interfaces",),
            ),
            IntentOperation(
                operation_id="routing.multiwan.capacity_weighted",
                feature="multiwan",
                resource="path_distribution_policy",
                attributes={
                    "mode": "capacity_weighted",
                    "weights": {"lab-wan10g": 10, "lab-wan1g": 1},
                    "failover": True,
                    "failback": "health_hysteresis",
                    "paths": {
                        "lab-wan10g": {
                            "interface": "ether2",
                            "addressing": "static",
                            "address": "192.0.2.2/30",
                            "gateway": "192.0.2.1",
                            "table": "to-lab-wan10g",
                            "failover_distance": 1,
                            "health_probe_targets": ["1.1.1.1", "8.8.8.8"],
                        },
                        "lab-wan1g": {
                            "interface": "ether3",
                            "addressing": "static",
                            "address": "198.51.100.2/30",
                            "gateway": "198.51.100.1",
                            "table": "to-lab-wan1g",
                            "failover_distance": 2,
                            "health_probe_targets": ["9.9.9.9", "208.67.222.222"],
                        },
                    },
                },
                risk=IntentRisk.HIGH,
                requires=("interfaces", "routing"),
            ),
        ),
    ).as_dict()


def _combined_commands() -> list[Mapping[str, Any]]:
    ir = _build_ir()
    base_plan = RouterOSSafeSubsetRenderer().render(ir).as_dict()
    pcc_plan = render_routeros_pcc(
        ir=ir,
        state={"firewall": {"filter": [], "nat": []}},
    ).as_dict()
    base_commands = base_plan.get("commands", [])
    pcc_commands = pcc_plan.get("commands", [])
    if not isinstance(base_commands, list) or not isinstance(pcc_commands, list):
        raise CHRPacketFlowError("renderer command collections must be lists")
    if len(base_commands) != 17 or len(pcc_commands) != 21:
        raise CHRPacketFlowError(
            f"packet-flow lab requires 17 recursive + 21 PCC commands; observed {len(base_commands)} + {len(pcc_commands)}"
        )
    return [*base_commands, *pcc_commands]


def _prepare_script() -> str:
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
        '/routing/settings/set check-gateway-ping-count=2 check-gateway-ping-interval=500ms check-gateway-ping-timeout=200ms',
        '/ip/address/add address="10.10.10.1/24" interface="ether4" comment="routercfg:lab:core-address"',
    ]
    commands = [str(item["command"]) for item in _combined_commands()]
    return "\n".join([*prelude, *commands]) + "\n"


def _route_rows(admin: base.LoopbackCHRAdmin) -> list[dict[str, Any]]:
    _, payload = admin.request("GET", "ip/route")
    rows: list[dict[str, Any]] = []
    for row in base._rows(payload):
        comment = str(row.get("comment") or "")
        if not comment.startswith("routercfg:managed:"):
            continue
        rows.append(
            {
                "comment": comment,
                "active": base._is_true(row.get("active")),
                "gateway": str(row.get("gateway") or ""),
                "routing_table": str(row.get("routing-table") or ""),
                "distance": str(row.get("distance") or ""),
            }
        )
    rows.sort(key=lambda row: row["comment"])
    return rows


def _matching(rows: list[dict[str, Any]], prefix: str) -> list[dict[str, Any]]:
    return [row for row in rows if str(row["comment"]).startswith(prefix)]


def _route_condition(rows: list[dict[str, Any]], expected: str) -> bool:
    w10_primary = _matching(
        rows,
        "routercfg:managed:pcc-route:lab-wan10g:lab-wan10g:",
    )
    w10_fallback = _matching(
        rows,
        "routercfg:managed:pcc-route:lab-wan10g:lab-wan1g:",
    )
    w1_primary = _matching(
        rows,
        "routercfg:managed:pcc-route:lab-wan1g:lab-wan1g:",
    )
    if not w10_primary or not w10_fallback or not w1_primary:
        return False
    if expected in {"normal", "recovered"}:
        return any(row["active"] for row in w10_primary) and any(
            row["active"] for row in w1_primary
        )
    if expected == "wan10_failed":
        return (
            not any(row["active"] for row in w10_primary)
            and any(row["active"] for row in w10_fallback)
            and any(row["active"] for row in w1_primary)
        )
    raise CHRPacketFlowError(f"unsupported route expectation: {expected}")


def prepare(*, admin_url: str, output: Path) -> dict[str, Any]:
    admin = base.LoopbackCHRAdmin(admin_url)
    platform = admin.assert_disposable_chr()
    _, interfaces_payload = admin.request("GET", "interface")
    names = {
        str(row.get("name") or "")
        for row in base._rows(interfaces_payload)
        if isinstance(row, Mapping)
    }
    required = {"ether1", "ether2", "ether3", "ether4"}
    missing = sorted(required - names)
    if missing:
        raise CHRPacketFlowError(f"packet-flow CHR is missing interfaces: {missing}")

    for name in TEMP_FILES:
        base._delete_file_if_present(admin, name)

    script = _prepare_script()
    try:
        chunked._create_text_file_chunk_verified(admin, APPLY_FILE, script)
        chunked._create_text_file_chunk_verified(admin, VERDICT_FILE, "PENDING")
        dry_run = base._execute_import_dry_run(
            admin,
            file_name=APPLY_FILE,
            verdict_name=VERDICT_FILE,
            expect_success=True,
        )
        apply_result = mutation._execute_import(
            admin,
            file_name=APPLY_FILE,
            expect_success=True,
        )
    finally:
        for name in TEMP_FILES:
            base._delete_file_if_present(admin, name)
        base._assert_files_absent(admin, TEMP_FILES)

    _, mangle_payload = admin.request("GET", "ip/firewall/mangle")
    managed_mangle = [
        row
        for row in base._rows(mangle_payload)
        if str(row.get("comment") or "").startswith("routercfg:managed:pcc-")
    ]
    rows = _route_rows(admin)
    if len(managed_mangle) != 13:
        raise CHRPacketFlowError(
            f"packet-flow lab expected 13 managed PCC mangle rules, observed {len(managed_mangle)}"
        )
    if len(_matching(rows, "routercfg:managed:pcc-route:")) != 8:
        raise CHRPacketFlowError("packet-flow lab expected 8 PCC policy routes")

    result = {
        "schema_version": "chr-packet-flow-prepare/1",
        "ok": True,
        "platform": {
            "version": str(platform.get("version") or ""),
            "architecture": str(platform.get("architecture-name") or ""),
            "board_name": str(platform.get("board-name") or ""),
        },
        "interfaces": sorted(names),
        "generated_command_count": 38,
        "pcc_mangle_count": len(managed_mangle),
        "pcc_policy_route_count": len(_matching(rows, "routercfg:managed:pcc-route:")),
        "dry_run": dry_run,
        "apply": apply_result,
        "lab_gateway_probe_interval": "500ms",
        "lab_gateway_probe_count": 2,
        "production_writer_available": False,
        "write_authorized": False,
    }
    output.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return result


def wait_routes(
    *,
    admin_url: str,
    expected: str,
    timeout_seconds: float,
    output: Path,
) -> dict[str, Any]:
    admin = base.LoopbackCHRAdmin(admin_url)
    admin.assert_disposable_chr()
    deadline = time.monotonic() + timeout_seconds
    attempts = 0
    last_rows: list[dict[str, Any]] = []
    while True:
        attempts += 1
        last_rows = _route_rows(admin)
        if _route_condition(last_rows, expected):
            break
        if time.monotonic() >= deadline:
            raise CHRPacketFlowError(
                f"route state did not reach {expected!r} within {timeout_seconds}s"
            )
        time.sleep(0.25)
    result = {
        "schema_version": "chr-packet-flow-route-state/1",
        "ok": True,
        "expected": expected,
        "attempts": attempts,
        "routes": last_rows,
    }
    output.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return result


def _load(path: Path) -> dict[str, Any]:
    value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise CHRPacketFlowError(f"evidence must be a JSON object: {path}")
    return value


def _phase_metrics(payload: Mapping[str, Any]) -> dict[str, Any]:
    requested = int(payload.get("requested_flows") or 0)
    successful = int(payload.get("successful_flows") or 0)
    tags = payload.get("tags", {})
    if not isinstance(tags, Mapping):
        tags = {}
    wan10 = int(tags.get("WAN10") or 0)
    wan1 = int(tags.get("WAN1") or 0)
    recognized = wan10 + wan1
    return {
        "requested": requested,
        "successful": successful,
        "success_ratio": successful / requested if requested else 0.0,
        "wan10": wan10,
        "wan1": wan1,
        "recognized": recognized,
        "wan10_share": wan10 / recognized if recognized else 0.0,
        "wan1_share": wan1 / recognized if recognized else 0.0,
        "unexpected_tags": successful - recognized,
    }


def evaluate(
    *,
    normal_path: Path,
    failover_path: Path,
    recovery_path: Path,
    failed_route_path: Path,
    recovered_route_path: Path,
    output: Path,
) -> dict[str, Any]:
    normal = _phase_metrics(_load(normal_path))
    failover = _phase_metrics(_load(failover_path))
    recovery = _phase_metrics(_load(recovery_path))
    failed_routes = _load(failed_route_path)
    recovered_routes = _load(recovered_route_path)

    errors: list[str] = []
    for label, metrics in (("normal", normal), ("recovery", recovery)):
        if metrics["success_ratio"] < 0.97:
            errors.append(f"{label}: successful flow ratio below 97%")
        if metrics["unexpected_tags"] != 0:
            errors.append(f"{label}: unexpected responder tags observed")
        if not 0.84 <= metrics["wan10_share"] <= 0.97:
            errors.append(
                f"{label}: WAN10 share {metrics['wan10_share']:.4f} is outside 10:1 tolerance"
            )
        if metrics["wan1"] <= 0:
            errors.append(f"{label}: WAN1 received no flows")

    if failover["success_ratio"] < 0.95:
        errors.append("failover: successful flow ratio below 95%")
    if failover["unexpected_tags"] != 0:
        errors.append("failover: unexpected responder tags observed")
    if failover["wan1_share"] < 0.98:
        errors.append(
            f"failover: WAN1 share {failover['wan1_share']:.4f} is below 98%"
        )
    if failed_routes.get("expected") != "wan10_failed" or failed_routes.get("ok") is not True:
        errors.append("failover route-state evidence is missing or invalid")
    if recovered_routes.get("expected") != "recovered" or recovered_routes.get("ok") is not True:
        errors.append("recovery route-state evidence is missing or invalid")

    result = {
        "schema_version": "chr-packet-flow-behavior-evidence/1",
        "ok": not errors,
        "acceptance": "PASS" if not errors else "FAIL",
        "errors": errors,
        "expected_capacity_ratio": "10:1",
        "normal": normal,
        "wan10_failure": failover,
        "recovered": recovery,
        "route_failure_observed": failed_routes.get("ok") is True,
        "route_recovery_observed": recovered_routes.get("ok") is True,
        "criteria": {
            "normal_and_recovery_success_ratio_min": 0.97,
            "normal_and_recovery_wan10_share_min": 0.84,
            "normal_and_recovery_wan10_share_max": 0.97,
            "failover_success_ratio_min": 0.95,
            "failover_wan1_share_min": 0.98,
        },
        "production_writer_available": False,
        "write_authorized": False,
    }
    output.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    if errors:
        raise CHRPacketFlowError("; ".join(errors))
    return result


def main() -> int:
    parser = argparse.ArgumentParser(description="Disposable CHR real packet-flow behavior verifier")
    sub = parser.add_subparsers(dest="command", required=True)

    prepare_parser = sub.add_parser("prepare")
    prepare_parser.add_argument("--admin-url", default="http://127.0.0.1:9380")
    prepare_parser.add_argument("--output", required=True)

    wait_parser = sub.add_parser("wait-routes")
    wait_parser.add_argument("--admin-url", default="http://127.0.0.1:9380")
    wait_parser.add_argument("--expected", choices=("normal", "wan10_failed", "recovered"), required=True)
    wait_parser.add_argument("--timeout-seconds", type=float, default=15.0)
    wait_parser.add_argument("--output", required=True)

    evaluate_parser = sub.add_parser("evaluate")
    evaluate_parser.add_argument("--normal", required=True)
    evaluate_parser.add_argument("--failover", required=True)
    evaluate_parser.add_argument("--recovery", required=True)
    evaluate_parser.add_argument("--failed-routes", required=True)
    evaluate_parser.add_argument("--recovered-routes", required=True)
    evaluate_parser.add_argument("--output", required=True)

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
                normal_path=Path(args.normal),
                failover_path=Path(args.failover),
                recovery_path=Path(args.recovery),
                failed_route_path=Path(args.failed_routes),
                recovered_route_path=Path(args.recovered_routes),
                output=Path(args.output),
            )
        print(json.dumps(result, indent=2, sort_keys=True))
        return 0
    except (OSError, ValueError, base.CHRRenderDryRunError, CHRPacketFlowError) as exc:
        failure = {
            "ok": False,
            "acceptance": "FAIL",
            "error": str(exc),
            "production_writer_available": False,
            "write_authorized": False,
        }
        output_value = getattr(args, "output", None)
        if output_value:
            output_path = Path(output_value)
            output_path.parent.mkdir(parents=True, exist_ok=True)
            output_path.write_text(json.dumps(failure, indent=2, sort_keys=True) + "\n", encoding="utf-8")
        print(json.dumps(failure, indent=2, sort_keys=True))
        return 17


if __name__ == "__main__":
    raise SystemExit(main())
