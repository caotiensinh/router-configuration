from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
from typing import Any, Mapping

import verify_render_dry_run as base
import verify_wireguard_handshake as verify


def _records(admin: base.LoopbackCHRAdmin, path: str) -> list[Mapping[str, Any]]:
    _, payload = admin.request("GET", path)
    return list(base._rows(payload))


def _fingerprint(value: str) -> str:
    return hashlib.sha256(value.encode("ascii", "strict")).hexdigest() if value else ""


def _peer(admin: base.LoopbackCHRAdmin, comment: str) -> dict[str, Any]:
    rows = [
        row for row in _records(admin, "interface/wireguard/peers")
        if str(row.get("comment") or "") == comment
    ]
    if len(rows) != 1:
        return {"present": False, "count": len(rows)}
    row = rows[0]
    return {
        "present": True,
        "last_handshake": str(row.get("last-handshake") or ""),
        "rx": str(row.get("rx") or "0"),
        "tx": str(row.get("tx") or "0"),
        "current_endpoint_address": str(row.get("current-endpoint-address") or ""),
        "current_endpoint_port": str(row.get("current-endpoint-port") or ""),
        "configured_endpoint_address": str(row.get("endpoint-address") or ""),
        "configured_endpoint_port": str(row.get("endpoint-port") or ""),
        "allowed_address": str(row.get("allowed-address") or ""),
        "public_key_sha256": _fingerprint(str(row.get("public-key") or "")),
        "invalid": base._is_true(row.get("invalid")),
        "disabled": base._is_true(row.get("disabled")),
    }


def _interface(admin: base.LoopbackCHRAdmin, name: str) -> dict[str, Any]:
    rows = [row for row in _records(admin, "interface/wireguard") if str(row.get("name") or "") == name]
    if len(rows) != 1:
        return {"present": False, "count": len(rows)}
    row = rows[0]
    return {
        "present": True,
        "listen_port": str(row.get("listen-port") or ""),
        "public_key_sha256": _fingerprint(str(row.get("public-key") or "")),
        "running": base._is_true(row.get("running")),
        "invalid": base._is_true(row.get("invalid")),
        "disabled": base._is_true(row.get("disabled")),
    }


def _routes(admin: base.LoopbackCHRAdmin, destination: str) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for row in _records(admin, "ip/route"):
        if str(row.get("dst-address") or "") != destination:
            continue
        rows.append(
            {
                "dst_address": destination,
                "gateway": str(row.get("gateway") or ""),
                "immediate_gw": str(row.get("immediate-gw") or ""),
                "active": base._is_true(row.get("active")),
                "invalid": base._is_true(row.get("invalid")),
                "disabled": base._is_true(row.get("disabled")),
                "comment": str(row.get("comment") or ""),
            }
        )
    return rows


def diagnose(*, admin_a_url: str, admin_b_url: str, phase: str) -> dict[str, Any]:
    admin_a = base.LoopbackCHRAdmin(admin_a_url)
    admin_b = base.LoopbackCHRAdmin(admin_b_url)
    admin_a.assert_disposable_chr()
    admin_b.assert_disposable_chr()
    admin_a.request("GET", "system/resource")
    admin_b.request("GET", "system/resource")
    return {
        "ok": True,
        "acceptance": "DIAGNOSTIC_ONLY",
        "phase": phase,
        "chr_a": {
            "management_rest_reachable": True,
            "interface": _interface(admin_a, verify.A_INTERFACE),
            "peer": _peer(admin_a, verify.A_PEER_COMMENT),
            "routes_to_remote_lan": _routes(admin_a, verify.B_LAN_NETWORK),
        },
        "chr_b": {
            "management_rest_reachable": True,
            "interface": _interface(admin_b, verify.B_INTERFACE),
            "peer": _peer(admin_b, verify.B_PEER_COMMENT),
            "routes_to_remote_lan": _routes(admin_b, verify.A_LAN_NETWORK),
        },
        "private_key_recorded": False,
        "private_key_serialized": False,
        "preshared_key_used": False,
        "production_writer_available": False,
        "transport_exposed_to_product": False,
        "write_authorized": False,
        "physical_router_targeted": False,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description="Capture safe WireGuard peer diagnostics from two disposable CHRs")
    parser.add_argument("--admin-a-url", default="http://127.0.0.1:10080")
    parser.add_argument("--admin-b-url", default="http://127.0.0.1:10081")
    parser.add_argument("--phase", required=True)
    parser.add_argument("--output", required=True)
    args = parser.parse_args()
    output = Path(args.output)
    output.parent.mkdir(parents=True, exist_ok=True)
    try:
        result = diagnose(admin_a_url=args.admin_a_url, admin_b_url=args.admin_b_url, phase=args.phase)
        rc = 0
    except (OSError, ValueError) as exc:
        result = {
            "ok": False,
            "acceptance": "DIAGNOSTIC_FAIL",
            "phase": args.phase,
            "error": str(exc),
            "private_key_recorded": False,
            "private_key_serialized": False,
        }
        rc = 1
    output.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(json.dumps(result, indent=2, sort_keys=True))
    return rc


if __name__ == "__main__":
    raise SystemExit(main())
