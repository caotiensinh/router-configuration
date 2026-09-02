import json
import unittest

from router_configuration.routeros_render_prerequisites import (
    RENDER_READ_SURFACES,
    RouterOSRenderPrerequisiteClient,
    RouterOSRenderPrerequisiteCollector,
    normalize_render_prerequisites,
)


class FakeClient:
    def get_surface(self, surface):
        return []


class FailingClient:
    def get_surface(self, surface):
        if surface == "routing_rules":
            raise RuntimeError("failure detail must not escape")
        return []


class RenderPrerequisiteTests(unittest.TestCase):
    def test_allowlist_contains_only_required_get_surfaces(self):
        self.assertEqual(
            RENDER_READ_SURFACES,
            {
                "bridges": "interface/bridge",
                "bridge_ports": "interface/bridge/port",
                "bridge_vlans": "interface/bridge/vlan",
                "vlan_interfaces": "interface/vlan",
                "queue_types": "queue/type",
                "routing_rules": "routing/rule",
            },
        )

    def test_client_builds_only_get_requests(self):
        client = RouterOSRenderPrerequisiteClient(
            base_url="https://192.0.2.10",
            username="reader",
            password="not-exported",
        )
        for surface, path in RENDER_READ_SURFACES.items():
            request = client.build_request(surface)
            self.assertEqual(request.method, "GET")
            self.assertEqual(request.full_url, f"https://192.0.2.10/rest/{path}")
        with self.assertRaisesRegex(ValueError, "allowlist"):
            client.build_request("system_script")

    def test_plain_http_requires_explicit_lab_boundary(self):
        with self.assertRaisesRegex(ValueError, "plain HTTP"):
            RouterOSRenderPrerequisiteClient(
                base_url="http://192.0.2.10",
                username="reader",
                password="x",
            )
        client = RouterOSRenderPrerequisiteClient(
            base_url="http://192.0.2.10",
            username="reader",
            password="x",
            allow_insecure_transport=True,
        )
        self.assertEqual(client.build_request("queue_types").method, "GET")

    def test_collector_reads_every_surface(self):
        report = RouterOSRenderPrerequisiteCollector(FakeClient()).collect_report()
        self.assertTrue(report.ok)
        self.assertEqual(set(report.data), set(RENDER_READ_SURFACES))
        self.assertEqual(report.errors, {})

    def test_collector_error_boundary_drops_exception_details(self):
        report = RouterOSRenderPrerequisiteCollector(FailingClient()).collect_report()
        self.assertFalse(report.ok)
        self.assertEqual(report.errors["routing_rules"], "RuntimeError")
        self.assertNotIn("failure detail", json.dumps(report.errors))

    def test_normalizer_groups_switching_qos_and_policy_state(self):
        raw = {
            "bridges": [{"name": "bridge-core", "vlan-filtering": "true"}],
            "bridge_ports": [{"interface": "ether2", "pvid": "10"}],
            "bridge_vlans": [{"vlan-ids": "10", "tagged": "bridge-core"}],
            "vlan_interfaces": [{"name": "vlan10", "vlan-id": "10"}],
            "queue_types": [{"name": "routercfg-fq-codel", "kind": "fq-codel"}],
            "routing_rules": [{"src-address": "192.168.20.0/24", "table": "to-wan1"}],
        }
        result = normalize_render_prerequisites(raw)
        self.assertEqual(result["schema_version"], "routeros-render-prerequisites/1")
        self.assertTrue(result["read_only"])
        self.assertFalse(result["write_methods_present"])
        self.assertTrue(result["switching"]["bridges"][0]["vlan-filtering"])
        self.assertEqual(result["qos"]["queue_types"][0]["kind"], "fq-codel")
        self.assertEqual(result["policy_routing"]["rules"][0]["table"], "to-wan1")

    def test_secret_like_fields_are_redacted(self):
        raw = {surface: [] for surface in RENDER_READ_SURFACES}
        raw["routing_rules"] = [{"token": "sensitive-value", "table": "to-wan1"}]
        result = normalize_render_prerequisites(raw)
        self.assertEqual(result["policy_routing"]["rules"][0]["token"], "<redacted>")
        self.assertNotIn("sensitive-value", json.dumps(result, sort_keys=True))

    def test_missing_or_unknown_surfaces_fail_closed(self):
        raw = {surface: [] for surface in RENDER_READ_SURFACES}
        del raw["bridge_vlans"]
        with self.assertRaisesRegex(ValueError, "missing render prerequisite"):
            normalize_render_prerequisites(raw)
        raw = {surface: [] for surface in RENDER_READ_SURFACES}
        raw["unknown"] = []
        with self.assertRaisesRegex(ValueError, "unknown render prerequisite"):
            normalize_render_prerequisites(raw)


if __name__ == "__main__":
    unittest.main()
