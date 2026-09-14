from __future__ import annotations

import json

import pytest

from router_configuration.lab_probes import (
    DNSProbeError,
    build_dns_query,
    build_dns_response,
    parse_dns_query,
    parse_dns_response,
    run_dns_probe,
    run_udp_flow_probe,
    write_json_evidence,
)


def test_dns_query_response_roundtrip() -> None:
    query = build_dns_query("routercfg.test")
    query_id, name, qtype, qclass, _end = parse_dns_query(query)
    assert query_id == 0x5243
    assert name == "routercfg.test."
    assert qtype == 1
    assert qclass == 1

    response = build_dns_response(query, answer_ip="192.0.2.53")
    assert parse_dns_response(response, expected_name="routercfg.test") == "192.0.2.53"


def test_dns_response_rejects_wrong_name() -> None:
    query = build_dns_query("routercfg.test")
    response = build_dns_response(query, answer_ip="192.0.2.53")
    with pytest.raises(DNSProbeError, match="unexpected DNS question name"):
        parse_dns_response(response, expected_name="other.test")


def test_dns_query_rejects_empty_name() -> None:
    with pytest.raises(DNSProbeError, match="at least one label"):
        build_dns_query(".")


def test_udp_flow_probe_rejects_invalid_parameters() -> None:
    with pytest.raises(ValueError, match="count must be positive"):
        run_udp_flow_probe(
            bind="127.0.0.1",
            destination="127.0.0.1",
            destination_port=5000,
            source_port_start=40000,
            count=0,
            timeout=0.1,
        )
    with pytest.raises(ValueError, match="dscp must be 0..63"):
        run_udp_flow_probe(
            bind="127.0.0.1",
            destination="127.0.0.1",
            destination_port=5000,
            source_port_start=40000,
            count=1,
            timeout=0.1,
            dscp=64,
        )


def test_dns_probe_rejects_invalid_expectation_before_network_access() -> None:
    with pytest.raises(DNSProbeError, match="unsupported expectation"):
        run_dns_probe(
            bind="127.0.0.1",
            server="127.0.0.1",
            port=5300,
            name="routercfg.test",
            expected_ip="192.0.2.53",
            timeout=0.1,
            expectation="maybe",
        )


def test_write_json_evidence_creates_parent_and_roundtrips(tmp_path) -> None:
    output = tmp_path / "nested" / "evidence.json"
    payload = {
        "schema_version": "network-device-test-evidence/1",
        "acceptance": "PASS",
        "production_writer_available": False,
        "write_authorized": False,
    }
    write_json_evidence(payload, output)
    assert json.loads(output.read_text(encoding="utf-8")) == payload
