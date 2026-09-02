import json
import unittest
from datetime import datetime, timezone

from router_configuration.routeros_capabilities import (
    assess_routeros_capabilities,
    parse_routeros_version,
)
from router_configuration.routeros_discovery import (
    READ_SURFACES,
    RouterOSDiscoveryCollector,
    normalize_routeros_snapshot,
)
from router_configuration.routeros_evidence import build_routeros_discovery_evidence


class FakeClient:
    def __init__(self, payload, fail=None):
        self.payload = payload
        self.fail = set(fail or [])
        self.calls = []

    def get_surface(self, surface):
        self.calls.append(surface)
        if surface in self.fail:
            raise RuntimeError("synthetic secret-bearing URL should never be persisted")
        return self.payload.get(surface, [])


PAYLOAD = {
    "system_identity": {"name": "lab-ccr2116"},
    "system_resource": {
        "version": "7.20.4 (stable)",
        "board-name": "CCR2116-12G-4S+",
        "architecture-name": "arm64",
    },
    "interfaces": [
        {".id": "*2", "name": "sfp-sfpplus2", "type": "ether", "running": "true", "disabled": "false"},
        {".id": "*1", "name": "sfp-sfpplus1", "type": "ether", "running": "true", "disabled": "false"},
    ],
    "ip_addresses": [{".id": "*A", "address": "192.0.2.1/24", "interface": "sfp-sfpplus2", "dynamic": "false"}],
    "ip_routes": [{".id": "*R1", "dst-address": "0.0.0.0/0", "gateway": "198.51.100.1", "distance": "1", "active": "true"}],
    "routing_tables": [{".id": "*T1", "name": "main", "fib": "true"}],
    "firewall_filter": [{".id": "*F1", "chain": "input", "action": "drop", "disabled": "false"}],
    "firewall_nat": [{".id": "*N1", "chain": "srcnat", "action": "masquerade", "out-interface": "sfp-sfpplus1"}],
    "wireguard_interfaces": [{".id": "*W1", "name": "wg-office", "listen-port": "51820", "private-key": "synthetic-private-key", "public-key": "synthetic-public-key"}],
    "wireguard_peers": [{".id": "*P1", "interface": "wg-office", "public-key": "peer-public-key", "preshared-key": "synthetic-psk", "allowed-address": "10.100.0.2/32"}],
    "queue_simple": [{".id": "*Q1", "name": "office", "max-limit": "100M/100M", "disabled": "false"}],
    "queue_tree": [],
}


class RouterOSEvidenceTests(unittest.TestCase):
    def test_version_baseline(self):
        self.assertFalse(parse_routeros_version("7.1beta3").supports_rest_read)
        self.assertTrue(parse_routeros_version("7.1beta4").supports_rest_read)
        self.assertTrue(parse_routeros_version("7.20.4 (stable)").supports_rest_read)
        self.assertFalse(parse_routeros_version("6.49.18").supports_rest_read)

    def test_partial_collection_uses_safe_error_codes(self):
        client = FakeClient(PAYLOAD, fail={"queue_tree"})
        report = RouterOSDiscoveryCollector(client).collect_report()
        self.assertEqual(report.errors, {"queue_tree": "RuntimeError"})
        self.assertNotIn("synthetic secret-bearing", json.dumps(report.errors))
        self.assertEqual(set(client.calls), set(READ_SURFACES))

    def test_capability_map_marks_missing_surface(self):
        raw = dict(PAYLOAD)
        raw.pop("wireguard_peers")
        state = normalize_routeros_snapshot(raw)
        assessment = assess_routeros_capabilities(state)
        self.assertTrue(assessment.rest_read_supported)
        self.assertFalse(dict(assessment.capabilities)["wireguard"])
        self.assertTrue(assessment.warnings)

    def test_evidence_is_redacted_and_digest_is_stable(self):
        state = normalize_routeros_snapshot(PAYLOAD)
        observed = datetime(2026, 9, 2, 1, 0, tzinfo=timezone.utc)
        first = build_routeros_discovery_evidence(state, observed_at=observed)
        second = build_routeros_discovery_evidence(state, observed_at=observed)
        self.assertEqual(first["state_sha256"], second["state_sha256"])
        rendered = json.dumps(first)
        self.assertNotIn("synthetic-private-key", rendered)
        self.assertNotIn("synthetic-psk", rendered)
        self.assertIn("<redacted>", rendered)
        self.assertTrue(first["capabilities"]["capabilities"]["routing"])

    def test_evidence_rejects_unredacted_secret_field(self):
        state = {"platform": {}, "private-key": "should-not-leak", "missing_surfaces": []}
        with self.assertRaisesRegex(ValueError, "unredacted"):
            build_routeros_discovery_evidence(state)


if __name__ == "__main__":
    unittest.main()
