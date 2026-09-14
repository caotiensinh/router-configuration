from __future__ import annotations

import argparse
import ipaddress
import json
import socket
import struct
import sys
import time
from pathlib import Path


QUERY_ID = 0x5243
QTYPE_A = 1
QCLASS_IN = 1


class DNSProbeError(RuntimeError):
    pass


def _encode_name(name: str) -> bytes:
    labels = [label for label in name.rstrip(".").split(".") if label]
    if not labels:
        raise DNSProbeError("DNS name must contain at least one label")
    encoded = bytearray()
    for label in labels:
        raw = label.encode("ascii")
        if len(raw) > 63:
            raise DNSProbeError("DNS label exceeds 63 bytes")
        encoded.append(len(raw))
        encoded.extend(raw)
    encoded.append(0)
    return bytes(encoded)


def _decode_name(data: bytes, offset: int) -> tuple[str, int]:
    labels: list[str] = []
    jumped = False
    return_offset = offset
    seen: set[int] = set()
    while True:
        if offset >= len(data):
            raise DNSProbeError("truncated DNS name")
        length = data[offset]
        if length & 0xC0 == 0xC0:
            if offset + 1 >= len(data):
                raise DNSProbeError("truncated DNS compression pointer")
            pointer = ((length & 0x3F) << 8) | data[offset + 1]
            if pointer in seen:
                raise DNSProbeError("DNS compression pointer loop")
            seen.add(pointer)
            if not jumped:
                return_offset = offset + 2
                jumped = True
            offset = pointer
            continue
        offset += 1
        if length == 0:
            if not jumped:
                return_offset = offset
            break
        if offset + length > len(data):
            raise DNSProbeError("truncated DNS label")
        labels.append(data[offset : offset + length].decode("ascii"))
        offset += length
    return ".".join(labels) + ".", return_offset


def build_query(name: str) -> bytes:
    header = struct.pack("!HHHHHH", QUERY_ID, 0x0100, 1, 0, 0, 0)
    question = _encode_name(name) + struct.pack("!HH", QTYPE_A, QCLASS_IN)
    return header + question


def parse_query(data: bytes) -> tuple[int, str, int, int, int]:
    if len(data) < 12:
        raise DNSProbeError("truncated DNS header")
    query_id, flags, qdcount, _ancount, _nscount, _arcount = struct.unpack(
        "!HHHHHH", data[:12]
    )
    if flags & 0x8000:
        raise DNSProbeError("expected DNS query, received response")
    if qdcount != 1:
        raise DNSProbeError(f"expected one DNS question, observed {qdcount}")
    name, offset = _decode_name(data, 12)
    if offset + 4 > len(data):
        raise DNSProbeError("truncated DNS question")
    qtype, qclass = struct.unpack("!HH", data[offset : offset + 4])
    return query_id, name, qtype, qclass, offset + 4


def build_response(query: bytes, *, answer_ip: str) -> bytes:
    query_id, _name, qtype, qclass, question_end = parse_query(query)
    if qtype != QTYPE_A or qclass != QCLASS_IN:
        raise DNSProbeError("only A/IN queries are accepted by the deterministic responder")
    ip_bytes = ipaddress.IPv4Address(answer_ip).packed
    header = struct.pack("!HHHHHH", query_id, 0x8580, 1, 1, 0, 0)
    question = query[12:question_end]
    answer = b"\xc0\x0c" + struct.pack("!HHIH", QTYPE_A, QCLASS_IN, 30, 4) + ip_bytes
    return header + question + answer


def parse_response(data: bytes, *, expected_name: str) -> str:
    if len(data) < 12:
        raise DNSProbeError("truncated DNS response header")
    query_id, flags, qdcount, ancount, _nscount, _arcount = struct.unpack(
        "!HHHHHH", data[:12]
    )
    if query_id != QUERY_ID:
        raise DNSProbeError(f"unexpected DNS transaction id: {query_id}")
    if not flags & 0x8000:
        raise DNSProbeError("DNS QR response bit is not set")
    if flags & 0x000F:
        raise DNSProbeError(f"DNS response RCODE is non-zero: {flags & 0x000F}")
    if qdcount != 1 or ancount < 1:
        raise DNSProbeError(
            f"unexpected DNS counts qdcount={qdcount} ancount={ancount}"
        )
    question_name, offset = _decode_name(data, 12)
    if question_name.lower() != expected_name.rstrip(".").lower() + ".":
        raise DNSProbeError(
            f"unexpected DNS question name {question_name!r}; expected {expected_name!r}"
        )
    if offset + 4 > len(data):
        raise DNSProbeError("truncated DNS response question")
    offset += 4
    _answer_name, offset = _decode_name(data, offset)
    if offset + 10 > len(data):
        raise DNSProbeError("truncated DNS answer header")
    rtype, rclass, _ttl, rdlength = struct.unpack("!HHIH", data[offset : offset + 10])
    offset += 10
    if rtype != QTYPE_A or rclass != QCLASS_IN or rdlength != 4:
        raise DNSProbeError("first DNS answer is not an IPv4 A/IN record")
    if offset + 4 > len(data):
        raise DNSProbeError("truncated DNS A record")
    return str(ipaddress.IPv4Address(data[offset : offset + 4]))


def serve(*, bind: str, port: int, answer_ip: str, name: str) -> int:
    expected = name.rstrip(".").lower() + "."
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.bind((bind, port))
        while True:
            payload, peer = sock.recvfrom(4096)
            try:
                _query_id, query_name, qtype, qclass, _end = parse_query(payload)
                if query_name.lower() != expected or qtype != QTYPE_A or qclass != QCLASS_IN:
                    continue
                response = build_response(payload, answer_ip=answer_ip)
            except (DNSProbeError, UnicodeError, ValueError):
                continue
            sock.sendto(response, peer)


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
    started = time.monotonic()
    observed = "unknown"
    answer_ip = ""
    error = ""
    try:
        query = build_query(name)
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
            sock.bind((bind, 0))
            sock.settimeout(timeout)
            sock.sendto(query, (server, port))
            response, peer = sock.recvfrom(4096)
            if peer[0] != server or peer[1] != port:
                raise DNSProbeError(f"unexpected DNS peer {peer[0]}:{peer[1]}")
            answer_ip = parse_response(response, expected_name=name)
            if answer_ip != expected_ip:
                raise DNSProbeError(
                    f"unexpected DNS A answer {answer_ip}; expected {expected_ip}"
                )
            observed = "success"
    except socket.timeout:
        observed = "timeout"
        error = "DNS query timed out"
    except (OSError, DNSProbeError, UnicodeError, ValueError) as exc:
        observed = "failure"
        error = f"{type(exc).__name__}: {exc}"

    if expectation == "success":
        ok = observed == "success"
    elif expectation == "failure":
        ok = observed != "success"
    else:
        raise DNSProbeError(f"unsupported expectation: {expectation}")

    result: dict[str, object] = {
        "schema_version": "chr-dns-service-probe/1",
        "ok": ok,
        "acceptance": "PASS" if ok else "FAIL",
        "expectation": expectation,
        "observed": observed,
        "bind": bind,
        "server": server,
        "port": port,
        "name": name,
        "expected_ip": expected_ip,
        "answer_ip": answer_ip,
        "timeout_seconds": timeout,
        "duration_seconds": round(time.monotonic() - started, 6),
        "error": error,
    }
    output.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8")
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
        return 0 if result["ok"] else 21
    except (DNSProbeError, OSError, ValueError) as exc:
        print(json.dumps({"ok": False, "acceptance": "FAIL", "error": str(exc)}))
        return 22


if __name__ == "__main__":
    raise SystemExit(main())
