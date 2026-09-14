from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

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


class LabProbeTests(unittest.TestCase):
    def test_dns_query_response_roundtrip(self) -> None:
        query = build_dns_query("routercfg.test")
        query_id, name, qtype, qclass, _end = parse_dns_query(query)
        self.assertEqual(query_id, 0x5243)
        self.assertEqual(name, "routercfg.test.")
        self.assertEqual(qtype, 1)
        self.assertEqual(qclass, 1)

        response = build_dns_response(query, answer_ip="192.0.2.53")
        self.assertEqual(
            parse_dns_response(response, expected_name="routercfg.test"),
            "192.0.2.53",
        )

    def test_dns_response_rejects_wrong_name(self) -> None:
        query = build_dns_query("routercfg.test")
        response = build_dns_response(query, answer_ip="192.0.2.53")
        with self.assertRaisesRegex(DNSProbeError, "unexpected DNS question name"):
            parse_dns_response(response, expected_name="other.test")

    def test_dns_query_rejects_empty_name(self) -> None:
        with self.assertRaisesRegex(DNSProbeError, "at least one label"):
            build_dns_query(".")

    def test_udp_flow_probe_rejects_invalid_parameters(self) -> None:
        with self.assertRaisesRegex(ValueError, "count must be positive"):
            run_udp_flow_probe(
                bind="127.0.0.1",
                destination="127.0.0.1",
                destination_port=5000,
                source_port_start=40000,
                count=0,
                timeout=0.1,
            )
        with self.assertRaisesRegex(ValueError, "dscp must be 0..63"):
            run_udp_flow_probe(
                bind="127.0.0.1",
                destination="127.0.0.1",
                destination_port=5000,
                source_port_start=40000,
                count=1,
                timeout=0.1,
                dscp=64,
            )

    def test_dns_probe_rejects_invalid_expectation_before_network_access(self) -> None:
        with self.assertRaisesRegex(DNSProbeError, "unsupported expectation"):
            run_dns_probe(
                bind="127.0.0.1",
                server="127.0.0.1",
                port=5300,
                name="routercfg.test",
                expected_ip="192.0.2.53",
                timeout=0.1,
                expectation="maybe",
            )

    def test_write_json_evidence_creates_parent_and_roundtrips(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            output = Path(temp_dir) / "nested" / "evidence.json"
            payload = {
                "schema_version": "network-device-test-evidence/1",
                "acceptance": "PASS",
                "production_writer_available": False,
                "write_authorized": False,
            }
            write_json_evidence(payload, output)
            self.assertEqual(
                json.loads(output.read_text(encoding="utf-8")), payload
            )


if __name__ == "__main__":
    unittest.main()
