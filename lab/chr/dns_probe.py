from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

_ROOT = Path(__file__).resolve().parents[2]
_SRC = _ROOT / "src"
if str(_SRC) not in sys.path:
    sys.path.insert(0, str(_SRC))

from router_configuration.lab_probes import (  # noqa: E402
    DNSProbeError,
    build_dns_query,
    build_dns_response,
    parse_dns_query,
    parse_dns_response,
    run_dns_probe,
    serve_dns,
    write_json_evidence,
)

# Preserve the legacy CHR probe API. Existing CHR acceptance code imports these
# names directly; only the implementation authority moves to the common core.
build_query = build_dns_query
parse_query = parse_dns_query
build_response = build_dns_response
parse_response = parse_dns_response


def serve(*, bind: str, port: int, answer_ip: str, name: str) -> int:
    return serve_dns(bind=bind, port=port, answer_ip=answer_ip, name=name)


def probe(
    *,
    bind: str,
    server: str,
    port: int,
    name: str,
    expected_ip: str,
    timeout: float,
    expectation: str,
    output: Path,
) -> dict[str, object]:
    result = run_dns_probe(
        bind=bind,
        server=server,
        port=port,
        name=name,
        expected_ip=expected_ip,
        timeout=timeout,
        expectation=expectation,
        schema_version="chr-dns-service-probe/1",
    )
    write_json_evidence(result, output)
    print(json.dumps(result, indent=2, sort_keys=True))
    return result


def main() -> int:
    parser = argparse.ArgumentParser()
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
            return serve(
                bind=args.bind,
                port=args.port,
                answer_ip=args.answer_ip,
                name=args.name,
            )
        result = probe(
            bind=args.bind,
            server=args.server,
            port=args.port,
            name=args.name,
            expected_ip=args.expected_ip,
            timeout=args.timeout,
            expectation=args.expect,
            output=Path(args.output),
        )
        return 0 if bool(result["ok"]) else 21
    except (DNSProbeError, OSError, UnicodeError, ValueError) as exc:
        print(json.dumps({"ok": False, "acceptance": "FAIL", "error": str(exc)}))
        return 22


if __name__ == "__main__":
    raise SystemExit(main())
