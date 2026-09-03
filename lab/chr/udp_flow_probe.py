from __future__ import annotations

import argparse
import json
import socket
import time
from collections import Counter
from pathlib import Path


def main() -> int:
    parser = argparse.ArgumentParser(description="Generate unique UDP flows through disposable CHR")
    parser.add_argument("--bind", required=True)
    parser.add_argument("--destination", required=True)
    parser.add_argument("--destination-port", type=int, default=5000)
    parser.add_argument("--source-port-start", type=int, required=True)
    parser.add_argument("--count", type=int, required=True)
    parser.add_argument("--timeout", type=float, default=0.35)
    parser.add_argument("--dscp", type=int, default=0)
    parser.add_argument("--output", required=True)
    args = parser.parse_args()

    if args.count <= 0:
        raise SystemExit("count must be positive")
    if not (1024 <= args.source_port_start <= 65535):
        raise SystemExit("source-port-start must be 1024..65535")
    if args.source_port_start + args.count - 1 > 65535:
        raise SystemExit("source port range exceeds 65535")
    if not (0 <= args.dscp <= 63):
        raise SystemExit("dscp must be 0..63")

    counts: Counter[str] = Counter()
    failures: list[dict[str, object]] = []
    started = time.monotonic()

    for index in range(args.count):
        source_port = args.source_port_start + index
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(args.timeout)
        sock.setsockopt(socket.IPPROTO_IP, socket.IP_TOS, args.dscp << 2)
        try:
            sock.bind((args.bind, source_port))
            payload = f"routercfg-flow:{source_port}:dscp={args.dscp}".encode("ascii")
            sock.sendto(payload, (args.destination, args.destination_port))
            response, _peer = sock.recvfrom(128)
            tag = response.decode("ascii", "replace").strip()
            counts[tag] += 1
        except (OSError, socket.timeout) as exc:
            failures.append(
                {
                    "source_port": source_port,
                    "error": type(exc).__name__,
                    "detail": str(exc)[:160],
                }
            )
        finally:
            sock.close()

    duration = time.monotonic() - started
    successes = sum(counts.values())
    result = {
        "schema_version": "chr-udp-flow-probe/1",
        "bind": args.bind,
        "destination": args.destination,
        "destination_port": args.destination_port,
        "source_port_start": args.source_port_start,
        "requested_flows": args.count,
        "successful_flows": successes,
        "failed_flows": len(failures),
        "success_ratio": successes / args.count,
        "dscp": args.dscp,
        "ip_tos": args.dscp << 2,
        "tags": dict(sorted(counts.items())),
        "duration_seconds": round(duration, 6),
        "failures": failures[:25],
    }
    output = Path(args.output)
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0 if successes else 16


if __name__ == "__main__":
    raise SystemExit(main())
