from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any, Mapping

import verify_qos_baseline as qos
import verify_render_dry_run as base


def _safe_rows(admin: base.LoopbackCHRAdmin, path: str, fields: tuple[str, ...]) -> list[dict[str, Any]]:
    _, payload = admin.request("GET", path)
    rows: list[dict[str, Any]] = []
    for row in base._rows(payload):
        rows.append({field: row[field] for field in fields if field in row})
    rows.sort(key=lambda item: json.dumps(item, sort_keys=True, ensure_ascii=False))
    return rows


def diagnose(*, admin_url: str) -> dict[str, Any]:
    try:
        return qos.verify_qos_baseline(admin_url=admin_url)
    except Exception as exc:  # diagnostic boundary intentionally records sanitized state
        admin = base.LoopbackCHRAdmin(admin_url)
        admin.assert_disposable_chr()
        return {
            "ok": False,
            "acceptance": "FAIL",
            "error": str(exc),
            "managed_mangle": [
                row
                for row in _safe_rows(
                    admin,
                    "ip/firewall/mangle",
                    (
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
                    ),
                )
                if str(row.get("comment") or "").startswith(qos.COMMENT_PREFIX)
            ],
            "managed_queue_tree": [
                row
                for row in _safe_rows(
                    admin,
                    "queue/tree",
                    (
                        "name",
                        "parent",
                        "packet-mark",
                        "queue",
                        "priority",
                        "limit-at",
                        "max-limit",
                        "disabled",
                        "invalid",
                    ),
                )
                if str(row.get("name") or "").startswith("routercfg-qos-")
            ],
            "managed_queue_type": [
                row
                for row in _safe_rows(admin, "queue/type", ("name", "kind"))
                if str(row.get("name") or "") == qos.QUEUE_TYPE
            ],
            "secrets_present": False,
            "physical_router_targeted": False,
            "production_writer_available": False,
            "write_authorized": False,
        }


def main() -> int:
    parser = argparse.ArgumentParser(description="Capture sanitized QoS CHR runtime diagnostics")
    parser.add_argument("--admin-url", default="http://127.0.0.1:9780")
    parser.add_argument("--output", required=True)
    args = parser.parse_args()
    result = diagnose(admin_url=args.admin_url)
    output = Path(args.output)
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0 if result.get("ok") else 15


if __name__ == "__main__":
    raise SystemExit(main())
