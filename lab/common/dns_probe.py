from __future__ import annotations

import argparse
import json
import signal
import sys
from pathlib import Path

_ROOT = Path(__file__).resolve().parents[2]
_SRC = _ROOT / "src"
if str(_SRC) not in sys.path:
    sys.path.insert(0, str(_SRC))

from router_configuration.lab_probes import (  # noqa: E402
    DNSProbeError,
    run_dns_probe,
    serve_dns,
    write_json_evidence,
)

_RUNNING = True


def _stop(_signum, _frame) -> None:
    global _RUNNING
    _RUNNING = False


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Vendor-neutral deterministic DNS service and probe for disposable network labs"
    )
    sub = parser.add_subparsers(dest="command", required=True)

    server = sub.add_parser("serve")
    server.add_argument("--bind", required=True)
    server.add_argument("--port", type=int, default=53)
    server.add_argument("--answer-ip", required=True)
    server.add_argument("--name", default="routercfg.test")

    client = sub.add_parser("probe")
    client.add_argument("--bind", required=True)
    client.add_argument("--server", required=True)
    client.add_argument("--port", type=int, default=53)
    client.add_argument("--name", default="routercfg.test")
    client.add_argument("--expected-ip", required=True)
    client.add_argument("--timeout", type=float, default=0.5)
    client.add_argument("--expect", choices=("success", "failure"), required=True)
    client.add_argument("--output", required=True)
    args = parser.parse_args()

    try:
        if args.command == "serve":
            signal.signal(signal.SIGTERM, _stop)
            signal.signal(signal.SIGINT, _stop)
            return serve_dns(
                bind=args.bind,
                port=args.port,
                answer_ip=args.answer_ip,
                name=args.name,
                should_stop=lambda: not _RUNNING,
            )

        result = run_dns_probe(
            bind=args.bind,
            server=args.server,
            port=args.port,
            name=args.name,
            expected_ip=args.expected_ip,
            timeout=args.timeout,
            expectation=args.expect,
            schema_version="network-device-dns-service-probe/1",
        )
        write_json_evidence(result, args.output)
        print(json.dumps(result, indent=2, sort_keys=True))
        return 0 if bool(result["ok"]) else 21
    except (DNSProbeError, OSError, UnicodeError, ValueError) as exc:
        print(json.dumps({"ok": False, "acceptance": "FAIL", "error": str(exc)}))
        return 22


if __name__ == "__main__":
    raise SystemExit(main())
