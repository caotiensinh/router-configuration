from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any, Mapping

import verify_render_dry_run as base


COMMENT_PREFIX = "routercfg:diag:qos:"
WAN_INTERFACE = "ether2"


def _rows(admin: base.LoopbackCHRAdmin) -> list[Mapping[str, Any]]:
    _, payload = admin.request("GET", "ip/firewall/mangle")
    return list(base._rows(payload))


def _find_by_comment(admin: base.LoopbackCHRAdmin, comment: str) -> Mapping[str, Any] | None:
    return next((row for row in _rows(admin) if str(row.get("comment") or "") == comment), None)


def _remove_by_comment(admin: base.LoopbackCHRAdmin, comment: str) -> None:
    row = _find_by_comment(admin, comment)
    if row is None:
        return
    row_id = str(row.get(".id") or "").strip()
    if not row_id:
        raise RuntimeError(f"diagnostic mangle row {comment!r} has no RouterOS id")
    admin.request("DELETE", f"ip/firewall/mangle/{row_id}")
    if _find_by_comment(admin, comment) is not None:
        raise RuntimeError(f"diagnostic mangle row {comment!r} was not removed")


def _safe_result(row: Mapping[str, Any]) -> dict[str, Any]:
    fields = (
        "chain",
        "out-interface",
        "dscp",
        "packet-mark",
        "action",
        "new-packet-mark",
        "passthrough",
        "comment",
        "disabled",
        "invalid",
    )
    return {field: row[field] for field in fields if field in row}


def _probe(
    admin: base.LoopbackCHRAdmin,
    *,
    name: str,
    payload: Mapping[str, Any],
) -> dict[str, Any]:
    comment = COMMENT_PREFIX + name
    _remove_by_comment(admin, comment)
    body = dict(payload)
    body["comment"] = comment
    body["disabled"] = False
    try:
        admin.request("PUT", "ip/firewall/mangle", body)
        row = _find_by_comment(admin, comment)
        if row is None:
            raise RuntimeError(f"RouterOS did not expose diagnostic rule {name!r}")
        result = _safe_result(row)
        result["variant"] = name
        result["invalid_observed"] = base._is_true(row.get("invalid"))
        return result
    finally:
        _remove_by_comment(admin, comment)


def diagnose_matrix(*, admin_url: str) -> dict[str, Any]:
    admin = base.LoopbackCHRAdmin(admin_url)
    platform = admin.assert_disposable_chr()
    if any(str(row.get("comment") or "").startswith(COMMENT_PREFIX) for row in _rows(admin)):
        raise RuntimeError("disposable CHR already contains QoS diagnostic mangle rows")

    common = {
        "chain": "forward",
        "out-interface": WAN_INTERFACE,
        "packet-mark": "no-mark",
        "action": "mark-packet",
        "new-packet-mark": "routercfg-qos-lab-wan-default",
        "passthrough": False,
    }
    variants = [
        (
            "exact_default",
            common,
            "current generated default classifier",
        ),
        (
            "alternate_mark_name",
            {**common, "new-packet-mark": "routercfg-qos-lab-wan-bulk"},
            "changes only the new packet-mark name",
        ),
        (
            "dscp_zero",
            {**common, "dscp": 0},
            "changes only by adding a DSCP matcher",
        ),
        (
            "without_packet_mark_match",
            {key: value for key, value in common.items() if key != "packet-mark"},
            "changes only by removing packet-mark=no-mark matcher",
        ),
        (
            "passthrough_yes",
            {**common, "passthrough": True},
            "changes only passthrough false to true",
        ),
    ]

    results = []
    for name, payload, changed_variable in variants:
        result = _probe(admin, name=name, payload=payload)
        result["changed_variable"] = changed_variable
        results.append(result)

    if any(str(row.get("comment") or "").startswith(COMMENT_PREFIX) for row in _rows(admin)):
        raise RuntimeError("QoS diagnostic matrix did not clean up all temporary mangle rows")

    return {
        "ok": True,
        "scope": "disposable_chr_qos_mangle_field_isolation",
        "platform": {
            "version": str(platform.get("version") or ""),
            "architecture": str(platform.get("architecture-name") or ""),
            "board_name": str(platform.get("board-name") or ""),
        },
        "variants": results,
        "temporary_rules_removed": True,
        "secrets_present": False,
        "physical_router_targeted": False,
        "production_writer_available": False,
        "write_authorized": False,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description="Isolate RouterOS QoS default-mangle invalidity")
    parser.add_argument("--admin-url", default="http://127.0.0.1:9780")
    parser.add_argument("--output", required=True)
    args = parser.parse_args()
    output = Path(args.output)
    output.parent.mkdir(parents=True, exist_ok=True)
    try:
        result = diagnose_matrix(admin_url=args.admin_url)
        rc = 0
    except Exception as exc:
        result = {
            "ok": False,
            "error": str(exc),
            "secrets_present": False,
            "physical_router_targeted": False,
            "production_writer_available": False,
            "write_authorized": False,
        }
        rc = 15
    output.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(json.dumps(result, indent=2, sort_keys=True))
    return rc


if __name__ == "__main__":
    raise SystemExit(main())
