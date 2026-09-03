from __future__ import annotations

import argparse
import json
import re
import subprocess
from pathlib import Path


SUMMARY_RE = re.compile(
    r"(?P<tx>\d+) packets transmitted, (?P<rx>\d+) received,.*?(?P<loss>[0-9.]+)% packet loss"
)


def main() -> int:
    parser = argparse.ArgumentParser(description="Measure ICMP packet delivery in a disposable network namespace")
    parser.add_argument("--destination", required=True)
    parser.add_argument("--count", type=int, required=True)
    parser.add_argument("--timeout", type=int, default=1)
    parser.add_argument("--output", required=True)
    args = parser.parse_args()

    if args.count <= 0:
        raise SystemExit("count must be positive")
    if args.timeout <= 0:
        raise SystemExit("timeout must be positive")

    completed = subprocess.run(
        [
            "ping",
            "-n",
            "-c",
            str(args.count),
            "-W",
            str(args.timeout),
            args.destination,
        ],
        check=False,
        capture_output=True,
        text=True,
        env={"PATH": "/usr/sbin:/usr/bin:/sbin:/bin", "LC_ALL": "C"},
    )
    combined = "\n".join(part for part in (completed.stdout, completed.stderr) if part)
    match = SUMMARY_RE.search(combined)
    if match is None:
        transmitted = args.count
        received = 0
        parse_ok = False
    else:
        transmitted = int(match.group("tx"))
        received = int(match.group("rx"))
        parse_ok = transmitted == args.count

    result = {
        "schema_version": "chr-icmp-probe/1",
        "destination": args.destination,
        "requested_packets": args.count,
        "transmitted_packets": transmitted,
        "received_packets": received,
        "failed_packets": max(transmitted - received, 0),
        "success_ratio": (received / transmitted) if transmitted else 0.0,
        "parse_ok": parse_ok,
        "process_returncode": completed.returncode,
    }
    output = Path(args.output)
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(json.dumps(result, indent=2, sort_keys=True))

    if parse_ok and received == transmitted == args.count:
        return 0
    if parse_ok and received == 0:
        return 16
    return 17


if __name__ == "__main__":
    raise SystemExit(main())
