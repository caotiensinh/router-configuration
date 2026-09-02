import json
import unittest
from pathlib import Path

from router_configuration.routeros_discovery import (
    READ_SURFACES,
    RouterOSDiscoveryCollector,
    RouterOSRestClient,
    normalize_routeros_snapshot,
)


FIXTURE = Path(__file__).parent / "fixtures" / "routeros_readonly_snapshot.json"


class FakeClient:
    def __init__(self, payload):
        self.payload = payload
        self.calls = []

    def get_surface(self, surface):
        self.calls.append(surface)
        return self.payload.get(surface, [])


class RouterOSDiscoveryTests(unittest.TestCase):
    def test_rest_client_builds_get_only_request(self):
        client = RouterOSRestClient("https://192.0.2.1", "reader", "secret")
        request = client.build_request("interfaces")
        self.assertEqual(request.get_method(), "GET")
        self.assertTrue(request.full_url.endswith("/rest/interface"))

    def test_rest_client_rejects_unknown_surface(self):
        client = RouterOSRestClient("https://192.0.2.1", "reader", "secret")
        with self.assertRaisesRegex(ValueError, "allowlist"):
            client.build_request("system/script/run")

    def test_plain_http_is_rejected_by_default(self):
        with self.assertRaisesRegex(ValueError, "plain HTTP"):
            RouterOSRestClient("http://192.0.2.1", "reader", "secret")

    def test_collector_only_reads_allowlisted_surfaces(self):
        payload = json.loads(FIXTURE.read_text(encoding="utf-8"))
        client = FakeClient(payload)
        collected = RouterOSDiscoveryCollector(client).collect()
        self.assertEqual(set(collected), set(READ_SURFACES))
        self.assertEqual(set(client.calls), set(READ_SURFACES))

    def test_normalizer_redacts_wireguard_secrets_and_is_deterministic(self):
        payload = json.loads(FIXTURE.read_text(encoding="utf-8"))
        first = normalize_routeros_snapshot(payload)
        second = normalize_routeros_snapshot(payload)
        self.assertEqual(first, second)
        self.assertEqual(first["platform"]["board_name"], "CCR2116-12G-4S+")
        self.assertEqual(first["wireguard"]["interfaces"][0]["private-key"], "<redacted>")
        self.assertEqual(first["wireguard"]["peers"][0]["preshared-key"], "<redacted>")
        self.assertTrue(first["interfaces"][0]["disabled"] is False)

    def test_unknown_fixture_surface_is_rejected(self):
        with self.assertRaisesRegex(ValueError, "unknown RouterOS"):
            normalize_routeros_snapshot({"dangerous_surface": []})


if __name__ == "__main__":
    unittest.main()
