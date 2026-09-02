import base64
import json
import threading
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

from router_configuration.routeros_discovery import (
    READ_SURFACES,
    RouterOSDiscoveryCollector,
    RouterOSRestClient,
    normalize_routeros_snapshot,
)
from router_configuration.routeros_evidence import build_routeros_discovery_evidence
from router_configuration.routeros_state_contract import verify_routeros_discovery_evidence


FIXTURE_DIR = Path(__file__).parent / "fixtures"
RAW_FIXTURE = FIXTURE_DIR / "routeros_readonly_snapshot.json"
GOLDEN_FIXTURE = FIXTURE_DIR / "routeros_normalized_golden.json"


class RouterOSFixtureHandler(BaseHTTPRequestHandler):
    payload = {}
    expected_authorization = ""
    seen_paths = []
    seen_methods = []

    def do_GET(self):  # noqa: N802 - BaseHTTPRequestHandler API
        type(self).seen_methods.append("GET")
        type(self).seen_paths.append(self.path)

        if self.headers.get("Authorization") != type(self).expected_authorization:
            self.send_response(401)
            self.end_headers()
            return

        reverse = {f"/rest/{path}": surface for surface, path in READ_SURFACES.items()}
        surface = reverse.get(self.path)
        if surface is None:
            self.send_response(404)
            self.end_headers()
            return

        body = json.dumps(type(self).payload.get(surface, [])).encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, _format, *args):
        return


class RouterOSHttpIntegrationTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        RouterOSFixtureHandler.payload = json.loads(RAW_FIXTURE.read_text(encoding="utf-8"))
        token = base64.b64encode(b"reader:synthetic-password").decode("ascii")
        RouterOSFixtureHandler.expected_authorization = f"Basic {token}"
        RouterOSFixtureHandler.seen_paths = []
        RouterOSFixtureHandler.seen_methods = []
        cls.server = ThreadingHTTPServer(("127.0.0.1", 0), RouterOSFixtureHandler)
        cls.thread = threading.Thread(target=cls.server.serve_forever, daemon=True)
        cls.thread.start()

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()
        cls.server.server_close()
        cls.thread.join(timeout=2)

    def test_real_http_get_path_matches_golden_state_and_verified_evidence(self):
        host, port = self.server.server_address
        client = RouterOSRestClient(
            base_url=f"http://{host}:{port}",
            username="reader",
            password="synthetic-password",
            allow_insecure_transport=True,
        )
        report = RouterOSDiscoveryCollector(client).collect_report()
        self.assertEqual(report.errors, {})

        state = normalize_routeros_snapshot(report.data)
        golden = json.loads(GOLDEN_FIXTURE.read_text(encoding="utf-8"))
        self.assertEqual(state, golden)

        evidence = build_routeros_discovery_evidence(state)
        verification = verify_routeros_discovery_evidence(evidence)
        self.assertTrue(verification.ok, verification.errors)

        rendered = json.dumps(evidence)
        self.assertNotIn("synthetic-private-key", rendered)
        self.assertNotIn("synthetic-psk", rendered)

        expected_paths = {f"/rest/{path}" for path in READ_SURFACES.values()}
        self.assertEqual(set(RouterOSFixtureHandler.seen_paths), expected_paths)
        self.assertEqual(set(RouterOSFixtureHandler.seen_methods), {"GET"})


if __name__ == "__main__":
    unittest.main()
