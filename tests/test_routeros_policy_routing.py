import unittest
from pathlib import Path

from router_configuration.routeros_discovery import RouterOSRestClient
from router_configuration.routeros_policy_routing import (
    RouterOSPolicyRoutingRestReader,
    collect_policy_routing_prerequisites,
)


class FakeReader:
    def __init__(self, payload):
        self.payload = payload
        self.calls = 0

    def read_rules(self):
        self.calls += 1
        return self.payload


class RouterOSPolicyRoutingTests(unittest.TestCase):
    def test_rest_reader_is_fixed_get_only_routing_rule_path(self):
        client = RouterOSRestClient(
            base_url="http://127.0.0.1:8080",
            username="reader",
            password="ephemeral-test-secret",
            verify_tls=False,
            allow_insecure_transport=True,
        )
        request = RouterOSPolicyRoutingRestReader(client).build_request()
        self.assertEqual(request.get_method(), "GET")
        self.assertEqual(request.full_url, "http://127.0.0.1:8080/rest/routing/rule")
        self.assertIn("Authorization", request.headers)

    def test_prerequisites_are_deterministic_and_generation_safe(self):
        first = FakeReader(
            [
                {".id": "*2", "src-address": "198.51.100.0/24", "disabled": "false"},
                {".id": "*1", "src-address": "192.0.2.0/24", "disabled": "true"},
            ]
        )
        second = FakeReader(list(reversed(first.payload)))
        a = collect_policy_routing_prerequisites(first).as_dict()
        b = collect_policy_routing_prerequisites(second).as_dict()
        self.assertEqual(a, b)
        self.assertEqual(first.calls, 1)
        self.assertEqual(a["schema_version"], "routeros-render-prerequisites/1")
        self.assertTrue(a["read_transport_used"])
        self.assertFalse(a["write_transport_present"])
        self.assertFalse(a["write_authorized"])
        rules = a["policy_routing"]["rules"]
        self.assertIs(rules[0]["disabled"], True)
        self.assertIs(rules[1]["disabled"], False)

    def test_secret_like_fields_are_redacted_before_prerequisite_output(self):
        reader = FakeReader(
            [{"comment": "lab", "token": "must-not-survive", "disabled": False}]
        )
        payload = collect_policy_routing_prerequisites(reader).as_dict()
        self.assertEqual(payload["policy_routing"]["rules"][0]["token"], "<redacted>")
        self.assertNotIn("must-not-survive", repr(payload))

    def test_non_object_routing_rule_entries_fail_closed(self):
        with self.assertRaisesRegex(ValueError, "entries must be objects"):
            collect_policy_routing_prerequisites(FakeReader(["not-an-object"]))

    def test_source_exposes_no_generic_or_write_request_surface(self):
        source = (
            Path(__file__).resolve().parents[1]
            / "src"
            / "router_configuration"
            / "routeros_policy_routing.py"
        ).read_text(encoding="utf-8")
        self.assertIn('_POLICY_ROUTING_PATH = "routing/rule"', source)
        self.assertNotIn("def request(", source)
        self.assertNotIn("def post(", source.lower())
        self.assertNotIn("def put(", source.lower())
        self.assertNotIn("def patch(", source.lower())
        self.assertNotIn("def delete(", source.lower())


if __name__ == "__main__":
    unittest.main()
