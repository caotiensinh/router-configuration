from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

# This script is intentionally colocated with the disposable CHR bootstrap and
# is never imported by the production package or command surface.
sys.path.insert(0, str(Path(__file__).resolve().parent))
from bootstrap_secure_acceptance import LabBootstrapError, LoopbackRestAdmin  # noqa: E402


COMMENT = "routercfg-disposable-live-acceptance"


def populate(admin_url: str) -> dict[str, object]:
    admin = LoopbackRestAdmin(admin_url)
    platform = admin.assert_disposable_chr()

    created: list[str] = []

    admin.request(
        "PUT",
        "ip/firewall/filter",
        {
            "chain": "input",
            "action": "accept",
            "protocol": "tcp",
            "dst-port": "443",
            "comment": COMMENT,
        },
    )
    created.append("firewall_filter")

    admin.request(
        "PUT",
        "ip/firewall/nat",
        {
            "chain": "srcnat",
            "action": "masquerade",
            "out-interface": "ether1",
            "comment": COMMENT,
        },
    )
    created.append("firewall_nat")

    admin.request(
        "PUT",
        "interface/wireguard",
        {
            "name": "wg-acceptance",
            "listen-port": "51820",
            "comment": COMMENT,
        },
    )
    created.append("wireguard_interface")

    admin.request(
        "PUT",
        "queue/simple",
        {
            "name": "qos-acceptance",
            "target": "10.0.2.0/24",
            "max-limit": "1M/1M",
            "comment": COMMENT,
        },
    )
    created.append("simple_queue")

    return {
        "ok": True,
        "scope": "disposable_chr_populated_surface_fixture",
        "platform": {
            "version": platform.get("version"),
            "architecture": platform.get("architecture-name"),
            "board_name": platform.get("board-name"),
        },
        "created_surfaces": created,
        "write_operations_performed": True,
        "production_writer_available": False,
    }


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Populate disposable loopback CHR with non-production test objects"
    )
    parser.add_argument("--admin-url", default="http://127.0.0.1:9180")
    args = parser.parse_args()
    try:
        payload = populate(args.admin_url)
    except LabBootstrapError as exc:
        print(json.dumps({"ok": False, "error": str(exc)}, indent=2, sort_keys=True))
        return 9
    print(json.dumps(payload, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
