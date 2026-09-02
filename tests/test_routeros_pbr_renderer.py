import hashlib
import json
import unittest

from router_configuration.routeros_pbr_renderer import (
    RouterOSPbrRenderError,
    render_routeros_pbr,
)


def ir_payload(source="192.168.20.0/24", table="to-wan10g", action="lookup"):
    payload = {
        "schema_version": "config-safe-subset-ir/1",
        "device_id": "router-01",
        "operations": [
            {
                "operation_id": "policy.pbr",
                "feature": "pbr",
                "resource": "policy_routing_rules",
                "attributes": {
                    "enabled": True,
                    "strategy": "routing_rules",
                    "mangle_routing_marks": False,
                    "rules": [
                        {
                            "name": "camera-egress",
                            "source_cidr": source,
                            "destination_cidr": "0.0.0.0/0",
                            "in_interface": "vlan20",
                            "table": table,
                            "action": action,
                            "fallback_to_main": action == "lookup",
                        }
                    ],
                },
                "risk": 30,
                "requires": ["routing"],
                "secret_references": [],
            },
            {
                "operation_id": "routing.multiwan.capacity_weighted",
                "feature": "multiwan",
                "resource": "path_distribution_policy",
                "attributes": {
                    "mode": "capacity_weighted",
                    "weights": {"wan10g": 10, "wan1g": 1},
                    "paths": {
                        "wan10g": {"table": "to-wan10g"},
                        "wan1g": {"table": "to-wan1g"},
                    },
                },
                "risk": 30,
                "requires": ["routing"],
                "secret_references": [],
            },
            {
                "operation_id": "security.baseline",
                "feature": "security",
                "resource": "firewall_baseline",
                "attributes": {
                    "profile": "enterprise_baseline",
                    "management_sources": ["192.168.99.0/24"],
                },
                "risk": 30,
                "requires": ["firewall"],
                "secret_references": [],
            },
        ],
        "vendor_commands_present": False,
        "write_transport_present": False,
    }
    payload["ir_sha256"] = hashlib.sha256(
        json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
    ).hexdigest()
    return payload


def state_payload():
    return {
        "routing_tables": [{"name": "main"}],
    }


def prerequisites(rules=None):
    return {
        "schema_version": "routeros-render-prerequisites/1",
        "policy_routing": {"rules": list(rules or [])},
    }


class RouterOSPbrRendererTests(unittest.TestCase):
    def test_generation_only_routing_rule_plan(self):
        plan = render_routeros_pbr(
            ir=ir_payload(),
            state=state_payload(),
            prerequisites=prerequisites(),
        ).as_dict()
        self.assertEqual(plan["strategy"], "routing_rules")
        self.assertFalse(plan["mangle_routing_marks"])
        self.assertFalse(plan["transport_present"])
        self.assertFalse(plan["apply_available"])
        self.assertFalse(plan["write_authorized"])
        self.assertEqual(plan["command_count"], 1)
        command = plan["commands"][0]["command"]
        self.assertIn("/routing/rule/add", command)
        self.assertIn('src-address="192.168.20.0/24"', command)
        self.assertIn('table="to-wan10g"', command)
        self.assertNotIn("/ip/firewall/mangle", command)

    def test_lookup_only_translates_to_routeros_action(self):
        plan = render_routeros_pbr(
            ir=ir_payload(action="lookup_only"),
            state=state_payload(),
            prerequisites=prerequisites(),
        ).as_dict()
        self.assertIn("action=lookup-only-in-table", plan["commands"][0]["command"])

    def test_management_overlap_is_blocked(self):
        with self.assertRaisesRegex(RouterOSPbrRenderError, "protected management"):
            render_routeros_pbr(
                ir=ir_payload(source="192.168.99.0/25"),
                state=state_payload(),
                prerequisites=prerequisites(),
            )

    def test_table_must_be_live_or_planned(self):
        with self.assertRaisesRegex(RouterOSPbrRenderError, "neither live nor planned"):
            render_routeros_pbr(
                ir=ir_payload(table="unknown-table"),
                state=state_payload(),
                prerequisites=prerequisites(),
            )

    def test_active_unmanaged_routing_rule_blocks_rendering(self):
        with self.assertRaisesRegex(RouterOSPbrRenderError, "unmanaged routing rules"):
            render_routeros_pbr(
                ir=ir_payload(),
                state=state_payload(),
                prerequisites=prerequisites(
                    [{".id": "*1", "src-address": "10.0.0.0/8", "disabled": False}]
                ),
            )

    def test_managed_routing_rule_is_reconcilable(self):
        plan = render_routeros_pbr(
            ir=ir_payload(),
            state=state_payload(),
            prerequisites=prerequisites(
                [
                    {
                        ".id": "*1",
                        "comment": "routercfg:managed:pbr:camera-egress",
                        "disabled": False,
                    }
                ]
            ),
        ).as_dict()
        self.assertIn("/routing/rule/set", plan["commands"][0]["command"])

    def test_missing_management_sources_blocks_rendering(self):
        ir = ir_payload()
        security = next(item for item in ir["operations"] if item["resource"] == "firewall_baseline")
        security["attributes"].pop("management_sources")
        unsigned = dict(ir)
        unsigned.pop("ir_sha256")
        ir["ir_sha256"] = hashlib.sha256(
            json.dumps(unsigned, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
        ).hexdigest()
        with self.assertRaisesRegex(RouterOSPbrRenderError, "explicit firewall management sources"):
            render_routeros_pbr(ir=ir, state=state_payload(), prerequisites=prerequisites())

    def test_tampered_ir_is_rejected(self):
        ir = ir_payload()
        ir["operations"][0]["attributes"]["strategy"] = "mangle"
        with self.assertRaisesRegex(RouterOSPbrRenderError, "digest mismatch"):
            render_routeros_pbr(ir=ir, state=state_payload(), prerequisites=prerequisites())


if __name__ == "__main__":
    unittest.main()
