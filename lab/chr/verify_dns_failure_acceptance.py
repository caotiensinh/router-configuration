from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any, Mapping


class CHRDNSFailureError(RuntimeError):
    pass


def _load(path: Path) -> Mapping[str, Any]:
    payload = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(payload, Mapping):
        raise CHRDNSFailureError(f"expected JSON object: {path}")
    return payload


def _is_true(value: object) -> bool:
    return str(value or "").strip().lower() in {"1", "true", "yes"}


def _dns_success(payload: Mapping[str, Any]) -> bool:
    return (
        payload.get("ok") is True
        and payload.get("acceptance") == "PASS"
        and payload.get("expectation") == "success"
        and payload.get("observed") == "success"
        and bool(str(payload.get("answer_ip") or ""))
    )


def _dns_failure(payload: Mapping[str, Any]) -> bool:
    if not (
        payload.get("ok") is True
        and payload.get("acceptance") == "PASS"
        and payload.get("expectation") == "failure"
        and payload.get("observed") != "success"
    ):
        return False
    error = str(payload.get("error") or "")
    # A response from the wrong WAN is not an accepted DNS outage.
    return "unexpected DNS A answer" not in error


def _connectivity_wan10(payload: Mapping[str, Any]) -> bool:
    requested = int(payload.get("requested_flows") or 0)
    successful = int(payload.get("successful_flows") or 0)
    tags = payload.get("tags", {})
    if not isinstance(tags, Mapping):
        return False
    return (
        requested > 0
        and successful == requested
        and int(tags.get("WAN10") or 0) == successful
        and int(tags.get("WAN1") or 0) == 0
    )


def _normal_routes(payload: Mapping[str, Any]) -> bool:
    if payload.get("ok") is not True or payload.get("expected") != "normal":
        return False
    rows = payload.get("routes", [])
    if not isinstance(rows, list):
        return False
    wan10 = [
        row
        for row in rows
        if isinstance(row, Mapping) and ":lab-wan10g:" in str(row.get("comment") or "")
    ]
    wan1 = [
        row
        for row in rows
        if isinstance(row, Mapping) and ":lab-wan1g:" in str(row.get("comment") or "")
    ]
    return (
        len(wan10) == 2
        and len(wan1) == 2
        and any(bool(row.get("active")) for row in wan10)
        and not any(bool(row.get("active")) for row in wan1)
    )


def _routeros_wan10_running(payload: object) -> bool:
    if not isinstance(payload, list):
        return False
    for row in payload:
        if isinstance(row, Mapping) and str(row.get("name") or "") == "ether2":
            return _is_true(row.get("running"))
    return False


def evaluate(
    *,
    dns_normal: Path,
    dns_failure: Path,
    dns_recovery: Path,
    connectivity_normal: Path,
    connectivity_failure: Path,
    connectivity_recovery: Path,
    routes_normal: Path,
    routes_failure: Path,
    routes_recovery: Path,
    failure_interfaces: Path,
    failed_sockets: Path,
    recovered_sockets: Path,
    output: Path,
) -> dict[str, Any]:
    dns = {
        "normal": _load(dns_normal),
        "failure": _load(dns_failure),
        "recovery": _load(dns_recovery),
    }
    connectivity = {
        "normal": _load(connectivity_normal),
        "failure": _load(connectivity_failure),
        "recovery": _load(connectivity_recovery),
    }
    routes = {
        "normal": _load(routes_normal),
        "failure": _load(routes_failure),
        "recovery": _load(routes_recovery),
    }
    interfaces = json.loads(failure_interfaces.read_text(encoding="utf-8"))
    stopped_socket_text = failed_sockets.read_text(encoding="utf-8", errors="replace")
    recovered_socket_text = recovered_sockets.read_text(encoding="utf-8", errors="replace")

    errors: list[str] = []
    if not _dns_success(dns["normal"]):
        errors.append("normal: deterministic DNS A lookup did not succeed")
    if not _dns_failure(dns["failure"]):
        errors.append("failure: DNS outage was not observed cleanly")
    if not _dns_success(dns["recovery"]):
        errors.append("recovery: deterministic DNS A lookup did not recover")

    for phase, payload in connectivity.items():
        if not _connectivity_wan10(payload):
            errors.append(
                f"{phase}: non-DNS data-plane connectivity did not remain fully on WAN10"
            )

    for phase, payload in routes.items():
        if not _normal_routes(payload):
            errors.append(
                f"{phase}: managed recursive routes did not remain in normal WAN10-preferred state"
            )

    if not _routeros_wan10_running(interfaces):
        errors.append("failure: RouterOS ether2 did not remain running")
    if ":53" in stopped_socket_text:
        errors.append("failure: WAN10 DNS responder socket was still listening")
    if ":53" not in recovered_socket_text:
        errors.append("recovery: WAN10 DNS responder socket did not return")

    result = {
        "schema_version": "chr-dns-failure-acceptance/1",
        "ok": not errors,
        "acceptance": "PASS" if not errors else "FAIL",
        "errors": errors,
        "semantics": {
            "dns_normal_success": _dns_success(dns["normal"]),
            "dns_failure_observed": _dns_failure(dns["failure"]),
            "dns_recovery_success": _dns_success(dns["recovery"]),
            "general_connectivity_remained_healthy": all(
                _connectivity_wan10(item) for item in connectivity.values()
            ),
            "wan10_route_remained_preferred": all(
                _normal_routes(item) for item in routes.values()
            ),
            "wan10_link_remained_up": _routeros_wan10_running(interfaces),
            "wan10_dns_socket_absent_during_failure": ":53" not in stopped_socket_text,
            "wan10_dns_socket_present_after_recovery": ":53" in recovered_socket_text,
        },
        "dns": dns,
        "connectivity": connectivity,
        "production_writer_available": False,
        "write_authorized": False,
    }
    output.write_text(
        json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    if errors:
        raise CHRDNSFailureError("; ".join(errors))
    return result


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--dns-normal", required=True)
    parser.add_argument("--dns-failure", required=True)
    parser.add_argument("--dns-recovery", required=True)
    parser.add_argument("--connectivity-normal", required=True)
    parser.add_argument("--connectivity-failure", required=True)
    parser.add_argument("--connectivity-recovery", required=True)
    parser.add_argument("--routes-normal", required=True)
    parser.add_argument("--routes-failure", required=True)
    parser.add_argument("--routes-recovery", required=True)
    parser.add_argument("--failure-interfaces", required=True)
    parser.add_argument("--failed-sockets", required=True)
    parser.add_argument("--recovered-sockets", required=True)
    parser.add_argument("--output", required=True)
    args = parser.parse_args()
    try:
        result = evaluate(
            dns_normal=Path(args.dns_normal),
            dns_failure=Path(args.dns_failure),
            dns_recovery=Path(args.dns_recovery),
            connectivity_normal=Path(args.connectivity_normal),
            connectivity_failure=Path(args.connectivity_failure),
            connectivity_recovery=Path(args.connectivity_recovery),
            routes_normal=Path(args.routes_normal),
            routes_failure=Path(args.routes_failure),
            routes_recovery=Path(args.routes_recovery),
            failure_interfaces=Path(args.failure_interfaces),
            failed_sockets=Path(args.failed_sockets),
            recovered_sockets=Path(args.recovered_sockets),
            output=Path(args.output),
        )
        print(json.dumps(result, indent=2, sort_keys=True))
        return 0
    except (OSError, ValueError, json.JSONDecodeError, CHRDNSFailureError) as exc:
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
        return 23


if __name__ == "__main__":
    raise SystemExit(main())
