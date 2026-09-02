from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any, Mapping

import verify_render_dry_run as base


WAN_INTERFACE = "ether2"
QUEUE_TYPE = "routercfg-diag-fq-codel"
PARENT = "routercfg-diag-qos-parent"
VOICE = "routercfg-diag-qos-voice"
DEFAULT = "routercfg-diag-qos-default"
COMMENT_PREFIX = "routercfg:diag:qos-order:"
MODES = {"batch-mangle", "interleaved", "leaves-first"}


def _rows(admin: base.LoopbackCHRAdmin, path: str) -> list[Mapping[str, Any]]:
    _, payload = admin.request("GET", path)
    return list(base._rows(payload))


def _by_name(admin: base.LoopbackCHRAdmin, path: str, name: str) -> Mapping[str, Any] | None:
    return next((row for row in _rows(admin, path) if str(row.get("name") or "") == name), None)


def _by_comment(admin: base.LoopbackCHRAdmin, comment: str) -> Mapping[str, Any] | None:
    return next(
        (
            row
            for row in _rows(admin, "ip/firewall/mangle")
            if str(row.get("comment") or "") == comment
        ),
        None,
    )


def _safe_row(row: Mapping[str, Any] | None) -> dict[str, Any] | None:
    if row is None:
        return None
    fields = (
        "name",
        "parent",
        "packet-mark",
        "queue",
        "priority",
        "chain",
        "out-interface",
        "dscp",
        "action",
        "new-packet-mark",
        "passthrough",
        "comment",
        "disabled",
        "invalid",
    )
    return {field: row[field] for field in fields if field in row}


def _snapshot(admin: base.LoopbackCHRAdmin) -> dict[str, Any]:
    return {
        "voice_mangle": _safe_row(_by_comment(admin, COMMENT_PREFIX + "voice")),
        "default_mangle": _safe_row(_by_comment(admin, COMMENT_PREFIX + "default")),
        "voice_leaf": _safe_row(_by_name(admin, "queue/tree", VOICE)),
        "default_leaf": _safe_row(_by_name(admin, "queue/tree", DEFAULT)),
    }


def _put_queue_type(admin: base.LoopbackCHRAdmin) -> None:
    admin.request("PUT", "queue/type", {"name": QUEUE_TYPE, "kind": "fq-codel"})


def _put_parent(admin: base.LoopbackCHRAdmin) -> None:
    admin.request(
        "PUT",
        "queue/tree",
        {
            "name": PARENT,
            "parent": WAN_INTERFACE,
            "max-limit": "100000000",
            "disabled": False,
        },
    )


def _put_mangle(admin: base.LoopbackCHRAdmin, *, voice: bool) -> None:
    name = VOICE if voice else DEFAULT
    body: dict[str, Any] = {
        "chain": "forward",
        "out-interface": WAN_INTERFACE,
        "packet-mark": "no-mark",
        "action": "mark-packet",
        "new-packet-mark": name,
        "passthrough": False,
        "disabled": False,
        "comment": COMMENT_PREFIX + ("voice" if voice else "default"),
    }
    if voice:
        body["dscp"] = 46
    admin.request("PUT", "ip/firewall/mangle", body)


def _put_leaf(admin: base.LoopbackCHRAdmin, *, voice: bool) -> None:
    name = VOICE if voice else DEFAULT
    admin.request(
        "PUT",
        "queue/tree",
        {
            "name": name,
            "parent": PARENT,
            "packet-mark": name,
            "queue": QUEUE_TYPE,
            "priority": 1 if voice else 8,
            "limit-at": "20000000" if voice else "80000000",
            "max-limit": "100000000",
            "disabled": False,
        },
    )


def _delete_by_id(admin: base.LoopbackCHRAdmin, path: str, row: Mapping[str, Any] | None) -> None:
    if row is None:
        return
    row_id = str(row.get(".id") or "").strip()
    if row_id:
        admin.request("DELETE", f"{path}/{row_id}")


def _cleanup(admin: base.LoopbackCHRAdmin) -> bool:
    for name in (DEFAULT, VOICE, PARENT):
        _delete_by_id(admin, "queue/tree", _by_name(admin, "queue/tree", name))
    for comment in (COMMENT_PREFIX + "default", COMMENT_PREFIX + "voice"):
        _delete_by_id(admin, "ip/firewall/mangle", _by_comment(admin, comment))
    _delete_by_id(admin, "queue/type", _by_name(admin, "queue/type", QUEUE_TYPE))
    return (
        _by_name(admin, "queue/type", QUEUE_TYPE) is None
        and all(_by_name(admin, "queue/tree", name) is None for name in (PARENT, VOICE, DEFAULT))
        and all(
            _by_comment(admin, comment) is None
            for comment in (COMMENT_PREFIX + "voice", COMMENT_PREFIX + "default")
        )
    )


def diagnose_creation_order(*, admin_url: str, mode: str) -> dict[str, Any]:
    if mode not in MODES:
        raise ValueError(f"unsupported QoS creation-order mode: {mode}")
    admin = base.LoopbackCHRAdmin(admin_url)
    platform = admin.assert_disposable_chr()
    if not _cleanup(admin):
        raise RuntimeError("could not establish a clean QoS creation-order baseline")

    steps: list[dict[str, Any]] = []

    def run(label: str, action) -> None:
        action()
        steps.append({"step": label, "state": _snapshot(admin)})

    try:
        run("queue-type", lambda: _put_queue_type(admin))
        run("parent", lambda: _put_parent(admin))
        if mode == "batch-mangle":
            run("voice-mangle", lambda: _put_mangle(admin, voice=True))
            run("default-mangle", lambda: _put_mangle(admin, voice=False))
            run("voice-leaf", lambda: _put_leaf(admin, voice=True))
            run("default-leaf", lambda: _put_leaf(admin, voice=False))
        elif mode == "interleaved":
            run("voice-mangle", lambda: _put_mangle(admin, voice=True))
            run("voice-leaf", lambda: _put_leaf(admin, voice=True))
            run("default-mangle", lambda: _put_mangle(admin, voice=False))
            run("default-leaf", lambda: _put_leaf(admin, voice=False))
        else:
            run("voice-leaf", lambda: _put_leaf(admin, voice=True))
            run("default-leaf", lambda: _put_leaf(admin, voice=False))
            run("voice-mangle", lambda: _put_mangle(admin, voice=True))
            run("default-mangle", lambda: _put_mangle(admin, voice=False))

        final_state = _snapshot(admin)
        admin.request("GET", "system/resource")
        return {
            "ok": True,
            "scope": "disposable_chr_qos_creation_order_isolation",
            "mode": mode,
            "platform": {
                "version": str(platform.get("version") or ""),
                "architecture": str(platform.get("architecture-name") or ""),
                "board_name": str(platform.get("board-name") or ""),
            },
            "steps": steps,
            "final_state": final_state,
            "management_rest_reachable": True,
            "throughput_acceptance": False,
            "latency_acceptance": False,
            "secrets_present": False,
            "physical_router_targeted": False,
            "production_writer_available": False,
            "transport_exposed_to_product": False,
            "write_authorized": False,
        }
    finally:
        cleaned = _cleanup(admin)
        if not cleaned:
            raise RuntimeError("QoS creation-order diagnostic cleanup failed")


def main() -> int:
    parser = argparse.ArgumentParser(description="Isolate RouterOS QoS packet-mark creation order")
    parser.add_argument("--admin-url", default="http://127.0.0.1:9790")
    parser.add_argument("--mode", choices=sorted(MODES), required=True)
    parser.add_argument("--output", required=True)
    args = parser.parse_args()
    output = Path(args.output)
    output.parent.mkdir(parents=True, exist_ok=True)
    try:
        result = diagnose_creation_order(admin_url=args.admin_url, mode=args.mode)
        rc = 0
    except Exception as exc:
        result = {
            "ok": False,
            "mode": args.mode,
            "error": str(exc),
            "throughput_acceptance": False,
            "latency_acceptance": False,
            "secrets_present": False,
            "physical_router_targeted": False,
            "production_writer_available": False,
            "transport_exposed_to_product": False,
            "write_authorized": False,
        }
        rc = 15
    output.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(json.dumps(result, indent=2, sort_keys=True))
    return rc


if __name__ == "__main__":
    raise SystemExit(main())
