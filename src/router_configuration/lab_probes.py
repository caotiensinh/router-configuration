from __future__ import annotations

import ipaddress
import json
import socket
import struct
import time
from collections import Counter
from pathlib import Path
from typing import Callable

DNS_QUERY_ID = 0x5243
DNS_QTYPE_A = 1
DNS_QCLASS_IN = 1


class DNSProbeError(RuntimeError):
    """Raised when deterministic DNS probe data is malformed or unexpected."""


def _never_stop() -> bool:
    return False


def write_json_evidence(payload: dict[str, object], output: str | Path) -> None:
    path = Path(output)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def serve_tagged_udp(
    *,
    bind: str,
    port: int,
    tag: str,
    should_stop: Callable[[], bool] | None = None,
) -> int:
    """Serve a deterministic UDP tag without any vendor-specific behavior."""

    stop = should_stop or _never_stop
    encoded_tag = tag.encode("ascii", "strict")
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.bind((bind, port))
        sock.settimeout(0.25)
        while not stop():
            try:
                payload, peer = sock.recvfrom(2048)
            except socket.timeout:
                continue
            if payload:
                sock.sendto(encoded_tag, peer)
    return 0


def run_udp_flow_probe(
    *,
    bind: str,
    destination: str,
    destination_port: int,
    source_port_start: int,
    count: int,
    timeout: float,
    dscp: int = 0,
    schema_version: str = "network-device-udp-flow-probe/1",
) -> dict[str, object]:
    """Generate unique UDP flows and classify replies by deterministic tag."""

    if count <= 0:
        raise ValueError("count must be positive")
    if not (1024 <= source_port_start <= 65535):
        raise ValueError("source_port_start must be 1024..65535")
    if source_port_start + count - 1 > 65535:
        raise ValueError("source port range exceeds 65535")
    if not (1 <= destination_port <= 65535):
        raise ValueError("destination_port must be 1..65535")
    if timeout <= 0:
        raise ValueError("timeout must be positive")
    if not (0 <= dscp <= 63):
        raise ValueError("dscp must be 0..63")
    if not schema_version.strip():
        raise ValueError("schema_version is required")

    counts: Counter[str] = Counter()
    failures: list[dict[str, object]] = []
    started = time.monotonic()

    for index in range(count):
        source_port = source_port_start + index
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
            sock.settimeout(timeout)
            sock.setsockopt(socket.IPPROTO_IP, socket.IP_TOS, dscp << 2)
            try:
                sock.bind((bind, source_port))
                payload = f"network-device-flow:{source_port}:dscp={dscp}".encode("ascii")
                sock.sendto(payload, (destination, destination_port))
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

    successes = sum(counts.values())
    return {
        "schema_version": schema_version,
        "bind": bind,
        "destination": destination,
        "destination_port": destination_port,
        "source_port_start": source_port_start,
        "requested_flows": count,
        "successful_flows": successes,
        "failed_flows": len(failures),
        "success_ratio": successes / count,
        "dscp": dscp,
        "ip_tos": dscp << 2,
        "tags": dict(sorted(counts.items())),
        "duration_seconds": round(time.monotonic() - started, 6),
        "failures": failures[:25],
    }


def _encode_dns_name(name: str) -> bytes:
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


def _decode_dns_name(data: bytes, offset: int) -> tuple[str, int]:
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


def build_dns_query(name: str) -> bytes:
    header = struct.pack("!HHHHHH", DNS_QUERY_ID, 0x0100, 1, 0, 0, 0)
    question = _encode_dns_name(name) + struct.pack("!HH", DNS_QTYPE_A, DNS_QCLASS_IN)
    return header + question


def parse_dns_query(data: bytes) -> tuple[int, str, int, int, int]:
    if len(data) < 12:
        raise DNSProbeError("truncated DNS header")
    query_id, flags, qdcount, _ancount, _nscount, _arcount = struct.unpack(
        "!HHHHHH", data[:12]
    )
    if flags & 0x8000:
        raise DNSProbeError("expected DNS query, received response")
    if qdcount != 1:
        raise DNSProbeError(f"expected one DNS question, observed {qdcount}")
    name, offset = _decode_dns_name(data, 12)
    if offset + 4 > len(data):
        raise DNSProbeError("truncated DNS question")
    qtype, qclass = struct.unpack("!HH", data[offset : offset + 4])
    return query_id, name, qtype, qclass, offset + 4


def build_dns_response(query: bytes, *, answer_ip: str) -> bytes:
    query_id, _name, qtype, qclass, question_end = parse_dns_query(query)
    if qtype != DNS_QTYPE_A or qclass != DNS_QCLASS_IN:
        raise DNSProbeError("only A/IN queries are accepted by the deterministic responder")
    ip_bytes = ipaddress.IPv4Address(answer_ip).packed
    header = struct.pack("!HHHHHH", query_id, 0x8580, 1, 1, 0, 0)
    question = query[12:question_end]
    answer = b"\xc0\x0c" + struct.pack(
        "!HHIH", DNS_QTYPE_A, DNS_QCLASS_IN, 30, 4
    ) + ip_bytes
    return header + question + answer


def parse_dns_response(data: bytes, *, expected_name: str) -> str:
    if len(data) < 12:
        raise DNSProbeError("truncated DNS response header")
    query_id, flags, qdcount, ancount, _nscount, _arcount = struct.unpack(
        "!HHHHHH", data[:12]
    )
    if query_id != DNS_QUERY_ID:
        raise DNSProbeError(f"unexpected DNS transaction id: {query_id}")
    if not flags & 0x8000:
        raise DNSProbeError("DNS QR response bit is not set")
    if flags & 0x000F:
        raise DNSProbeError(f"DNS response RCODE is non-zero: {flags & 0x000F}")
    if qdcount != 1 or ancount < 1:
        raise DNSProbeError(
            f"unexpected DNS counts qdcount={qdcount} ancount={ancount}"
        )
    question_name, offset = _decode_dns_name(data, 12)
    if question_name.lower() != expected_name.rstrip(".").lower() + ".":
        raise DNSProbeError(
            f"unexpected DNS question name {question_name!r}; expected {expected_name!r}"
        )
    if offset + 4 > len(data):
        raise DNSProbeError("truncated DNS response question")
    offset += 4
    _answer_name, offset = _decode_dns_name(data, offset)
    if offset + 10 > len(data):
        raise DNSProbeError("truncated DNS answer header")
    rtype, rclass, _ttl, rdlength = struct.unpack("!HHIH", data[offset : offset + 10])
    offset += 10
    if rtype != DNS_QTYPE_A or rclass != DNS_QCLASS_IN or rdlength != 4:
        raise DNSProbeError("first DNS answer is not an IPv4 A/IN record")
    if offset + 4 > len(data):
        raise DNSProbeError("truncated DNS A record")
    return str(ipaddress.IPv4Address(data[offset : offset + 4]))


def serve_dns(
    *,
    bind: str,
    port: int,
    answer_ip: str,
    name: str,
    should_stop: Callable[[], bool] | None = None,
) -> int:
    """Serve one deterministic A record without vendor-specific dependencies."""

    stop = should_stop or _never_stop
    expected = name.rstrip(".").lower() + "."
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.bind((bind, port))
        sock.settimeout(0.25)
        while not stop():
            try:
                payload, peer = sock.recvfrom(4096)
            except socket.timeout:
                continue
            try:
                _query_id, query_name, qtype, qclass, _end = parse_dns_query(payload)
                if (
                    query_name.lower() != expected
                    or qtype != DNS_QTYPE_A
                    or qclass != DNS_QCLASS_IN
                ):
                    continue
                response = build_dns_response(payload, answer_ip=answer_ip)
            except (DNSProbeError, UnicodeError, ValueError):
                continue
            sock.sendto(response, peer)
    return 0


def run_dns_probe(
    *,
    bind: str,
    server: str,
    port: int,
    name: str,
    expected_ip: str,
    timeout: float,
    expectation: str,
    schema_version: str = "network-device-dns-service-probe/1",
) -> dict[str, object]:
    """Probe deterministic DNS success/failure and return machine evidence."""

    if expectation not in {"success", "failure"}:
        raise DNSProbeError(f"unsupported expectation: {expectation}")
    if timeout <= 0:
        raise DNSProbeError("timeout must be positive")
    if not (1 <= port <= 65535):
        raise DNSProbeError("port must be 1..65535")

    started = time.monotonic()
    observed = "unknown"
    answer_ip = ""
    error = ""
    try:
        query = build_dns_query(name)
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
            sock.bind((bind, 0))
            sock.settimeout(timeout)
            sock.sendto(query, (server, port))
            response, peer = sock.recvfrom(4096)
            if peer[0] != server or peer[1] != port:
                raise DNSProbeError(f"unexpected DNS peer {peer[0]}:{peer[1]}")
            answer_ip = parse_dns_response(response, expected_name=name)
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

    ok = observed == "success" if expectation == "success" else observed != "success"
    return {
        "schema_version": schema_version,
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
