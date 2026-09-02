from __future__ import annotations

import argparse
import signal
import socket


_RUNNING = True


def _stop(_signum, _frame) -> None:
    global _RUNNING
    _RUNNING = False


def main() -> int:
    parser = argparse.ArgumentParser(description="WAN-tagged UDP responder for disposable CHR flow tests")
    parser.add_argument("--bind", required=True)
    parser.add_argument("--port", type=int, default=5000)
    parser.add_argument("--tag", required=True)
    args = parser.parse_args()

    signal.signal(signal.SIGTERM, _stop)
    signal.signal(signal.SIGINT, _stop)

    tag = args.tag.encode("ascii", "strict")
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind((args.bind, args.port))
    sock.settimeout(0.5)
    try:
        while _RUNNING:
            try:
                payload, peer = sock.recvfrom(2048)
            except socket.timeout:
                continue
            if not payload:
                continue
            sock.sendto(tag, peer)
    finally:
        sock.close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
