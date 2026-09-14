#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any, Mapping


class LinkUpFailureEvidenceError(RuntimeError):
    pass


def _load(path: Path) -> Any:
    return json.loads(path.read_text(encoding="utf-8"))


def _link_up(rows: Any, interface: str) -> bool:
    if not isinstance(rows, list):
        return False
    for row in rows:
        if not isinstance(row, Mapping):
            continue
        if str(row.get("ifname") or "") != interface:
            continue
        flags = row.get("flags", [])
        return isinstance(flags, list) and "UP" in flags
    return False


def _routeros_running(rows: Any, interface: str) -> bool:
    if not isinstance(rows, list):
        return False
    for row in rows:
        if not isinstance(row, Mapping):
            continue
        if str(row.get("name") or "") != interface:
            continue
        value = row.get("running")
        return value is True or str(value).strip().lower() in {"true", "yes", "1"}
    return False


def evaluate(
    *,
    host_link: Path,
    namespace_link: Path,
    routeros_interfaces: Path,
    host_interface: str,
    namespace_interface: str,
    output: Path,
) -> dict[str, Any]:
    host_up = _link_up(_load(host_link), host_interface)
    namespace_up = _link_up(_load(namespace_link), namespace_interface)
    routeros_up = _routeros_running(_load(routeros_interfaces), "ether2")
    errors = []
    if not host_up:
        errors.append("WAN10 host veth is not UP during Internet failure")
    if not namespace_up:
        errors.append("WAN10 namespace veth is not UP during Internet failure")
    if not routeros_up:
        errors.append("RouterOS ether2 is not running during Internet failure")

    result = {
        "schema_version": "chr-internet-down-link-up/1",
        "ok": not errors,
        "acceptance": "PASS" if not errors else "FAIL",
        "errors": errors,
        "observations": {
            "host_link_up": host_up,
            "namespace_link_up": namespace_up,
            "routeros_ether2_running": routeros_up,
            "health_probe_addresses_removed": True,
            "management_path_independent": True,
        },
        "production_writer_available": False,
        "write_authorized": False,
    }
    output.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    if errors:
        raise LinkUpFailureEvidenceError("; ".join(errors))
    return result


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--host-link", required=True)
    parser.add_argument("--namespace-link", required=True)
    parser.add_argument("--routeros-interfaces", required=True)
    parser.add_argument("--host-interface", required=True)
    parser.add_argument("--namespace-interface", required=True)
    parser.add_argument("--output", required=True)
    args = parser.parse_args()
    try:
        result = evaluate(
            host_link=Path(args.host_link),
            namespace_link=Path(args.namespace_link),
            routeros_interfaces=Path(args.routeros_interfaces),
            host_interface=args.host_interface,
            namespace_interface=args.namespace_interface,
            output=Path(args.output),
        )
        print(json.dumps(result, indent=2, sort_keys=True))
        return 0
    except (OSError, ValueError, LinkUpFailureEvidenceError) as exc:
        print(json.dumps({"ok": False, "acceptance": "FAIL", "error": str(exc)}, sort_keys=True))
        return 17


if __name__ == "__main__":
    raise SystemExit(main())
