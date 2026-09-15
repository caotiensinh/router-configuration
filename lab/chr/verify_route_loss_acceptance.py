from __future__ import annotations

import argparse
import json
import time
from pathlib import Path
from typing import Any, Mapping

import verify_render_dry_run as base


class CHRRouteLossError(RuntimeError):
    pass


def _load(path: Path) -> Mapping[str, Any]:
    payload = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(payload, Mapping):
        raise CHRRouteLossError(f"expected JSON object: {path}")
    return payload


def _is_true(value: object) -> bool:
    return str(value or "").strip().lower() in {"1", "true", "yes"}


def _managed_defaults(admin: base.LoopbackCHRAdmin) -> list[dict[str, Any]]:
    _, payload = admin.request("GET", "ip/route")
    _, active_payload = admin.request("GET", "ip/route?active=true")
    active_ids = {
        str(row.get(".id") or "")
        for row in base._rows(active_payload)
        if str(row.get(".id") or "")
    }
    rows: list[dict[str, Any]] = []
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
                "disabled": _is_true(row.get("disabled")),
                "dynamic": _is_true(row.get("dynamic")),
                "distance": str(row.get("distance") or ""),
                "gateway": str(row.get("gateway") or ""),
                "immediate_gateway": str(row.get("immediate-gw") or ""),
                "routing_table": str(row.get("routing-table") or ""),
            }
        )
    rows.sort(key=lambda item: item["comment"])
    return rows


def _control_route_state(rows: list[Mapping[str, Any]], expected: str) -> bool:
    """Validate direct REST control snapshots, including disabled ownership state."""
    wan10 = [row for row in rows if ":lab-wan10g:" in str(row.get("comment") or "")]
    wan1 = [row for row in rows if ":lab-wan1g:" in str(row.get("comment") or "")]
    if len(wan10) != 2 or len(wan1) != 2:
        return False
    if any(bool(row.get("dynamic")) for row in [*wan10, *wan1]):
        return False
    if expected in {"normal", "recovered"}:
        return (
            all(not bool(row.get("disabled")) for row in wan10)
            and any(bool(row.get("active")) for row in wan10)
            and not any(bool(row.get("active")) for row in wan1)
        )
    if expected == "route_loss":
        return (
            all(bool(row.get("disabled")) for row in wan10)
            and not any(bool(row.get("active")) for row in wan10)
            and any(bool(row.get("active")) for row in wan1)
        )
    raise CHRRouteLossError(f"unsupported route state: {expected}")


def _active_route_state(rows: list[Mapping[str, Any]], expected: str) -> bool:
    """Validate wait-routes evidence, which intentionally contains active state only."""
    wan10 = [row for row in rows if ":lab-wan10g:" in str(row.get("comment") or "")]
    wan1 = [row for row in rows if ":lab-wan1g:" in str(row.get("comment") or "")]
    if len(wan10) != 2 or len(wan1) != 2:
        return False
    if expected in {"normal", "recovered"}:
        return any(bool(row.get("active")) for row in wan10) and not any(
            bool(row.get("active")) for row in wan1
        )
    if expected == "route_loss":
        return not any(bool(row.get("active")) for row in wan10) and any(
            bool(row.get("active")) for row in wan1
        )
    raise CHRRouteLossError(f"unsupported active route state: {expected}")


def set_preferred_state(
    *, admin_url: str, disabled: bool, output: Path, timeout_seconds: float = 15.0
) -> dict[str, Any]:
    admin = base.LoopbackCHRAdmin(admin_url)
    platform = admin.assert_disposable_chr()
    before = _managed_defaults(admin)
    expected_before = "normal" if disabled else "route_loss"
    expected_after = "route_loss" if disabled else "recovered"
    if not _control_route_state(before, expected_before):
        raise CHRRouteLossError(
            f"refusing route-state mutation: precondition {expected_before!r} not met"
        )

    preferred = [
        row for row in before if ":lab-wan10g:" in str(row.get("comment") or "")
    ]
    target_ids = [str(row.get("route_id") or "") for row in preferred]
    if len(target_ids) != 2 or any(not route_id for route_id in target_ids):
        raise CHRRouteLossError("preferred WAN10 default-route ownership set is incomplete")

    for route_id in target_ids:
        admin.request(
            "PATCH",
            f"ip/route/{route_id}",
            {"disabled": "true" if disabled else "false"},
        )

    deadline = time.monotonic() + timeout_seconds
    after: list[dict[str, Any]] = []
    while True:
        after = _managed_defaults(admin)
        if _control_route_state(after, expected_after):
            break
        if time.monotonic() >= deadline:
            raise CHRRouteLossError(
                f"RouterOS route state did not reach {expected_after!r} within {timeout_seconds}s"
            )
        time.sleep(0.25)

    result = {
        "schema_version": "chr-route-loss-control/1",
        "ok": True,
        "acceptance": "PASS",
        "operation": "disable_preferred_defaults" if disabled else "restore_preferred_defaults",
        "expected_before": expected_before,
        "expected_after": expected_after,
        "target_route_ids": target_ids,
        "before": before,
        "after": after,
        "platform": {
            "version": str(platform.get("version") or ""),
            "architecture": str(platform.get("architecture-name") or ""),
            "board_name": str(platform.get("board-name") or ""),
        },
        "lab_setup_write_operations_performed": True,
        "production_writer_available": False,
        "write_authorized": False,
    }
    output.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return result


def _flow_on(payload: Mapping[str, Any], expected_tag: str) -> bool:
    requested = int(payload.get("requested_flows") or 0)
    successful = int(payload.get("successful_flows") or 0)
    tags = payload.get("tags", {})
    if not isinstance(tags, Mapping):
        return False
    other = "WAN1" if expected_tag == "WAN10" else "WAN10"
    return (
        requested > 0
        and successful == requested
        and int(tags.get(expected_tag) or 0) == successful
        and int(tags.get(other) or 0) == 0
    )


def _wait_route_evidence(payload: Mapping[str, Any], expected: str) -> bool:
    expected_map = {
        "normal": "normal",
        "route_loss": "wan10_failed",
        "recovered": "recovered",
    }
    if payload.get("ok") is not True or payload.get("expected") != expected_map[expected]:
        return False
    rows = payload.get("routes", [])
    if not isinstance(rows, list):
        return False
    return _active_route_state(
        [row for row in rows if isinstance(row, Mapping)], expected
    )


def _routeros_wan10_running(payload: object) -> bool:
    if not isinstance(payload, list):
        return False
    for row in payload:
        if isinstance(row, Mapping) and str(row.get("name") or "") == "ether2":
            return _is_true(row.get("running"))
    return False


def _linux_link_up(payload: object, ifname: str) -> bool:
    if not isinstance(payload, list):
        return False
    for row in payload:
        if not isinstance(row, Mapping) or str(row.get("ifname") or "") != ifname:
            continue
        flags = row.get("flags", [])
        return isinstance(flags, list) and "UP" in {str(value) for value in flags}
    return False


def _control_ok(payload: Mapping[str, Any], operation: str, expected_after: str) -> bool:
    if (
        payload.get("ok") is not True
        or payload.get("acceptance") != "PASS"
        or payload.get("operation") != operation
        or payload.get("expected_after") != expected_after
    ):
        return False
    ids = payload.get("target_route_ids", [])
    return isinstance(ids, list) and len(ids) == 2 and all(bool(str(x)) for x in ids)


def evaluate(
    *,
    flow_normal: Path,
    flow_loss: Path,
    flow_recovery: Path,
    routes_normal: Path,
    routes_loss: Path,
    routes_recovery: Path,
    loss_control: Path,
    recovery_control: Path,
    failure_interfaces: Path,
    host_link: Path,
    namespace_link: Path,
    host_interface: str,
    namespace_interface: str,
    output: Path,
) -> dict[str, Any]:
    flows = {
        "normal": _load(flow_normal),
        "route_loss": _load(flow_loss),
        "recovery": _load(flow_recovery),
    }
    routes = {
        "normal": _load(routes_normal),
        "route_loss": _load(routes_loss),
        "recovery": _load(routes_recovery),
    }
    controls = {
        "loss": _load(loss_control),
        "recovery": _load(recovery_control),
    }
    interfaces = json.loads(failure_interfaces.read_text(encoding="utf-8"))
    host = json.loads(host_link.read_text(encoding="utf-8"))
    namespace = json.loads(namespace_link.read_text(encoding="utf-8"))

    semantics = {
        "normal_flow_on_wan10": _flow_on(flows["normal"], "WAN10"),
        "route_loss_flow_on_wan1": _flow_on(flows["route_loss"], "WAN1"),
        "recovery_flow_on_wan10": _flow_on(flows["recovery"], "WAN10"),
        "normal_route_state": _wait_route_evidence(routes["normal"], "normal"),
        "preferred_default_routes_lost": _wait_route_evidence(
            routes["route_loss"], "route_loss"
        ),
        "preferred_default_routes_recovered": _wait_route_evidence(
            routes["recovery"], "recovered"
        ),
        "route_loss_control_valid": _control_ok(
            controls["loss"], "disable_preferred_defaults", "route_loss"
        ),
        "route_recovery_control_valid": _control_ok(
            controls["recovery"], "restore_preferred_defaults", "recovered"
        ),
        "routeros_wan10_link_remained_up": _routeros_wan10_running(interfaces),
        "host_wan10_link_remained_up": _linux_link_up(host, host_interface),
        "namespace_wan10_link_remained_up": _linux_link_up(
            namespace, namespace_interface
        ),
        "same_routes_restored": controls["loss"].get("target_route_ids")
        == controls["recovery"].get("target_route_ids"),
    }
    errors = [name for name, ok in semantics.items() if not ok]
    result = {
        "schema_version": "chr-route-loss-acceptance/1",
        "ok": not errors,
        "acceptance": "PASS" if not errors else "FAIL",
        "errors": errors,
        "semantics": semantics,
        "flows": flows,
        "controls": controls,
        "production_writer_available": False,
        "write_authorized": False,
    }
    output.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    if errors:
        raise CHRRouteLossError("; ".join(errors))
    return result


def main() -> int:
    parser = argparse.ArgumentParser()
    sub = parser.add_subparsers(dest="command", required=True)

    state = sub.add_parser("set-state")
    state.add_argument("--admin-url", default="http://127.0.0.1:9380")
    state.add_argument("--disabled", choices=("true", "false"), required=True)
    state.add_argument("--timeout-seconds", type=float, default=15.0)
    state.add_argument("--output", required=True)

    check = sub.add_parser("evaluate")
    for name in (
        "flow-normal",
        "flow-loss",
        "flow-recovery",
        "routes-normal",
        "routes-loss",
        "routes-recovery",
        "loss-control",
        "recovery-control",
        "failure-interfaces",
        "host-link",
        "namespace-link",
        "host-interface",
        "namespace-interface",
        "output",
    ):
        check.add_argument(f"--{name}", required=True)

    args = parser.parse_args()
    try:
        if args.command == "set-state":
            result = set_preferred_state(
                admin_url=args.admin_url,
                disabled=args.disabled == "true",
                timeout_seconds=args.timeout_seconds,
                output=Path(args.output),
            )
        else:
            result = evaluate(
                flow_normal=Path(args.flow_normal),
                flow_loss=Path(args.flow_loss),
                flow_recovery=Path(args.flow_recovery),
                routes_normal=Path(args.routes_normal),
                routes_loss=Path(args.routes_loss),
                routes_recovery=Path(args.routes_recovery),
                loss_control=Path(args.loss_control),
                recovery_control=Path(args.recovery_control),
                failure_interfaces=Path(args.failure_interfaces),
                host_link=Path(args.host_link),
                namespace_link=Path(args.namespace_link),
                host_interface=args.host_interface,
                namespace_interface=args.namespace_interface,
                output=Path(args.output),
            )
        print(json.dumps(result, indent=2, sort_keys=True))
        return 0
    except (OSError, ValueError, json.JSONDecodeError, base.CHRRenderDryRunError, CHRRouteLossError) as exc:
        failure = {
            "ok": False,
            "acceptance": "FAIL",
            "error": str(exc),
            "production_writer_available": False,
            "write_authorized": False,
        }
        Path(args.output).write_text(
            json.dumps(failure, indent=2, sort_keys=True) + "\n", encoding="utf-8"
        )
        print(json.dumps(failure, indent=2, sort_keys=True))
        return 26


if __name__ == "__main__":
    raise SystemExit(main())
