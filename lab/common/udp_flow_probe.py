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
    run_udp_flow_probe,
    write_json_evidence,
)


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Generate vendor-neutral UDP flows through a disposable network lab"
    )
    parser.add_argument("--bind", required=True)
    parser.add_argument("--destination", required=True)
    parser.add_argument("--destination-port", type=int, default=5000)
    parser.add_argument("--source-port-start", type=int, required=True)
    parser.add_argument("--count", type=int, required=True)
    parser.add_argument("--timeout", type=float, default=0.35)
    parser.add_argument("--dscp", type=int, default=0)
    parser.add_argument("--output", required=True)
    args = parser.parse_args()

    result = run_udp_flow_probe(
        bind=args.bind,
        destination=args.destination,
        destination_port=args.destination_port,
        source_port_start=args.source_port_start,
        count=args.count,
        timeout=args.timeout,
        dscp=args.dscp,
        schema_version="network-device-udp-flow-probe/1",
    )
    write_json_evidence(result, args.output)
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0 if int(result["successful_flows"]) > 0 else 16


if __name__ == "__main__":
    raise SystemExit(main())
