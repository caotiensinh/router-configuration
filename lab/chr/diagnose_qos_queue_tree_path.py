from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any, Mapping

import verify_mutation_rollback as mutation
import verify_qos_packet_flow as legacy
import verify_render_dry_run as base
import verify_render_dry_run_chunked as chunked


DIAG_FILE = "routercfg-qos-queue-path-diag.rsc"
DIAG_INTERFACE = "routercfg-qos-diag-interface"
DIAG_GLOBAL = "routercfg-qos-diag-global"


def _read(path: str | Path) -> Any:
    return json.loads(Path(path).read_text(encoding="utf-8"))


def _write(path: str | Path, payload: Mapping[str, Any]) -> None:
    output = Path(path)
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def _rows(admin: base.LoopbackCHRAdmin, path: str) -> list[Mapping[str, Any]]:
    _, payload = admin.request("GET", path)
    return list(base._rows(payload))


def _queue_stats(admin: base.LoopbackCHRAdmin) -> list[Mapping[str, Any]]:
    _, payload = admin.request("POST", "queue/tree/print", {"stats": ""})
    return list(base._rows(payload))


def _execute(admin: base.LoopbackCHRAdmin, script: str) -> Mapping[str, Any]:
    for name in (DIAG_FILE, mutation.VERDICT_FILE):
        base._delete_file_if_present(admin, name)
    try:
        chunked._create_text_file_chunk_verified(admin, DIAG_FILE, script)
        return mutation._execute_import(admin, file_name=DIAG_FILE, expect_success=True)
    finally:
        for name in (DIAG_FILE, mutation.VERDICT_FILE):
            base._delete_file_if_present(admin, name)


def _quote(value: str) -> str:
    return '"' + value.replace("\\", "\\\\").replace('"', '\\"') + '"'


def inspect(*, admin_url: str) -> dict[str, Any]:
    admin = base.LoopbackCHRAdmin(admin_url)
    platform = admin.assert_disposable_chr()
    _, settings_payload = admin.request("GET", "ip/settings")
    settings = dict(settings_payload) if isinstance(settings_payload, Mapping) else {}
    filters = _rows(admin, "ip/firewall/filter")
    fasttrack = [
        {
            key: row.get(key)
            for key in (".id", "chain", "action", "connection-state", "disabled", "comment")
            if key in row
        }
        for row in filters
        if str(row.get("action") or "") == "fasttrack-connection"
    ]
    interfaces = _rows(admin, "interface")
    selected_interfaces = [
        {
            key: row.get(key)
            for key in ("name", "type", "running", "disabled", "rx-byte", "tx-byte", "rx-packet", "tx-packet")
            if key in row
        }
        for row in interfaces
        if str(row.get("name") or "") in {"ether2", "ether3"}
    ]
    return {
        "ok": True,
        "scope": "disposable_chr_qos_queue_path_environment",
        "platform": {
            "version": platform.get("version"),
            "architecture": platform.get("architecture-name"),
            "board_name": platform.get("board-name"),
        },
        "ip_settings": {
            key: settings.get(key)
            for key in (
                "allow-fast-path",
                "ipv4-fast-path-active",
                "ipv4-fast-path-packets",
                "ipv4-fast-path-bytes",
                "route-cache",
            )
            if key in settings
        },
        "fasttrack_rule_count": len(fasttrack),
        "fasttrack_rules": fasttrack,
        "interfaces": selected_interfaces,
        "production_writer_available": False,
        "physical_router_targeted": False,
    }


def install(*, admin_url: str, prepare_payload: Mapping[str, Any], mode: str) -> dict[str, Any]:
    admin = base.LoopbackCHRAdmin(admin_url)
    admin.assert_disposable_chr()
    target = prepare_payload.get("target")
    if not isinstance(target, Mapping):
        raise legacy.CHRQoSPacketFlowError("queue path diagnostic requires production prepare target")
    mark = str(target.get("packet_mark") or "")
    interface = str(target.get("interface") or "")
    if not mark or interface != "ether2":
        raise legacy.CHRQoSPacketFlowError("queue path diagnostic requires rendered ether2 EF packet mark")
    if mode not in {"interface", "global"}:
        raise legacy.CHRQoSPacketFlowError("queue path diagnostic mode must be interface or global")

    owned_names = (
        str(target.get("priority_queue") or ""),
        str(target.get("default_queue") or ""),
        str(target.get("parent_queue") or ""),
        DIAG_INTERFACE,
        DIAG_GLOBAL,
    )
    removals = [f"/queue/tree/remove [find where name={_quote(name)}]" for name in owned_names if name]
    diag_name = DIAG_INTERFACE if mode == "interface" else DIAG_GLOBAL
    parent = interface if mode == "interface" else "global"
    add = (
        f"/queue/tree/add name={_quote(diag_name)} parent={_quote(parent)} "
        f"packet-mark={_quote(mark)} queue=default-small max-limit=100M disabled=no"
    )
    execute = _execute(admin, "\n".join((*removals, add)) + "\n")

    matches = [row for row in _rows(admin, "queue/tree") if str(row.get("name") or "") == diag_name]
    if len(matches) != 1:
        raise legacy.CHRQoSPacketFlowError(f"diagnostic {mode} queue cardinality is {len(matches)}")
    row = matches[0]
    invalid = base._is_true(row.get("invalid"))
    disabled = base._is_true(row.get("disabled"))
    return {
        "ok": True,
        "mode": mode,
        "name": diag_name,
        "parent": str(row.get("parent") or ""),
        "packet_mark": str(row.get("packet-mark") or ""),
        "queue": str(row.get("queue") or ""),
        "invalid": invalid,
        "disabled": disabled,
        "runtime_valid": not invalid and not disabled,
        "execute": dict(execute),
        "production_hierarchy_removed_for_diagnostic": True,
        "production_renderer_modified": False,
        "production_writer_available": False,
        "physical_router_targeted": False,
    }


def stats(*, admin_url: str, name: str) -> dict[str, Any]:
    admin = base.LoopbackCHRAdmin(admin_url)
    admin.assert_disposable_chr()
    matches = [row for row in _queue_stats(admin) if str(row.get("name") or "") == name]
    if len(matches) != 1:
        raise legacy.CHRQoSPacketFlowError(f"diagnostic stats expected one {name}, observed {len(matches)}")
    row = matches[0]
    invalid = base._is_true(row.get("invalid"))
    disabled = base._is_true(row.get("disabled"))
    return {
        "ok": True,
        "name": name,
        "parent": str(row.get("parent") or ""),
        "packet_mark": str(row.get("packet-mark") or ""),
        "queue": str(row.get("queue") or ""),
        "invalid": invalid,
        "disabled": disabled,
        "runtime_valid": not invalid and not disabled,
        "packets": legacy._int_counter(row, "packets", name),
        "bytes": legacy._int_counter(row, "bytes", name),
        "queued_packets": int(str(row.get("queued-packets") or "0")),
        "dropped": int(str(row.get("dropped") or "0")),
        "counter_source": "queue_tree_print_stats",
    }


def cleanup(*, admin_url: str) -> dict[str, Any]:
    admin = base.LoopbackCHRAdmin(admin_url)
    admin.assert_disposable_chr()
    execute = _execute(
        admin,
        "\n".join(
            (
                f"/queue/tree/remove [find where name={_quote(DIAG_INTERFACE)}]",
                f"/queue/tree/remove [find where name={_quote(DIAG_GLOBAL)}]",
            )
        )
        + "\n",
    )
    remaining = [
        str(row.get("name") or "")
        for row in _rows(admin, "queue/tree")
        if str(row.get("name") or "") in {DIAG_INTERFACE, DIAG_GLOBAL}
    ]
    if remaining:
        raise legacy.CHRQoSPacketFlowError(f"diagnostic queues remained after cleanup: {remaining}")
    return {"ok": True, "execute": dict(execute), "diagnostic_queues_removed": True}


def main() -> int:
    parser = argparse.ArgumentParser(description="Isolate RouterOS Queue Tree attachment behavior on disposable CHR")
    sub = parser.add_subparsers(dest="command", required=True)

    p = sub.add_parser("inspect")
    p.add_argument("--admin-url", required=True)
    p.add_argument("--output", required=True)

    p = sub.add_parser("install")
    p.add_argument("--admin-url", required=True)
    p.add_argument("--prepare", required=True)
    p.add_argument("--mode", choices=("interface", "global"), required=True)
    p.add_argument("--output", required=True)

    p = sub.add_parser("stats")
    p.add_argument("--admin-url", required=True)
    p.add_argument("--name", required=True)
    p.add_argument("--output", required=True)

    p = sub.add_parser("cleanup")
    p.add_argument("--admin-url", required=True)
    p.add_argument("--output", required=True)

    args = parser.parse_args()
    if args.command == "inspect":
        result = inspect(admin_url=args.admin_url)
    elif args.command == "install":
        result = install(admin_url=args.admin_url, prepare_payload=_read(args.prepare), mode=args.mode)
    elif args.command == "stats":
        result = stats(admin_url=args.admin_url, name=args.name)
    else:
        result = cleanup(admin_url=args.admin_url)
    _write(args.output, result)
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
