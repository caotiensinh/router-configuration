from __future__ import annotations

import argparse
import signal
import sys
from pathlib import Path

_ROOT = Path(__file__).resolve().parents[2]
_SRC = _ROOT / "src"
if str(_SRC) not in sys.path:
    sys.path.insert(0, str(_SRC))

from router_configuration.lab_probes import serve_tagged_udp  # noqa: E402

_RUNNING = True


def _stop(_signum, _frame) -> None:
    global _RUNNING
    _RUNNING = False


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Vendor-neutral WAN-tagged UDP responder for disposable network labs"
    )
    parser.add_argument("--bind", required=True)
    parser.add_argument("--port", type=int, default=5000)
    parser.add_argument("--tag", required=True)
    args = parser.parse_args()

    signal.signal(signal.SIGTERM, _stop)
    signal.signal(signal.SIGINT, _stop)
    return serve_tagged_udp(
        bind=args.bind,
        port=args.port,
        tag=args.tag,
        should_stop=lambda: not _RUNNING,
    )


if __name__ == "__main__":
    raise SystemExit(main())
