import hashlib
import json
import unittest

from router_configuration.routeros_qos_renderer import RouterOSQoSRenderError, render_routeros_qos


def ir_payload():
    payload = {
        "schema_version": "config-safe-subset-ir/1",
        "device_id": "router-01",
        "operations": [
            {
                "operation_id": "qos.policy",
                "feature": "qos",
                "resource": "traffic_policy",
                "attributes": {
                    "enabled": True,
                    "policy": "latency_sensitive_first",
                    "classification": "existing_dscp_only",
                    "queue_kind": "fq-codel",
                    "egress_limits_mbps": {"wan10g": 9500, "wan1g": 950},
                    "classes": [
                        {"name": "voice", "priority": 1, "bandwidth_percent": 20, "default": False, "dscp": [46]},
                        {"name": "video", "priority": 3, "bandwidth_percent": 30, "default": False, "dscp": [34, 36]},
                        {"name": "default", "priority": 8, "bandwidth_percent": 50, "default": True, "dscp": []},
                    ],
                },
                "risk": 20,
                "requires": ["qos"],
                "secret_references": [],
            },
            {
                "operation_id": "topology.wan.wan10g",
                "feature": "topology",
                "resource": "wan_role",
                "attributes": {"name": "wan10g", "interface": "sfp-sfpplus1", "capacity_mbps": 10000, "addressing": "static"},
                "risk": 20,
                "requires": ["interfaces"],
                "secret_references": [],
            },
            {
                "operation_id": "topology.wan.wan1g",
                "feature": "topology",
                "resource": "wan_role",
                "attributes": {"name": "wan1g", "interface": "ether1", "capacity_mbps": 1000, "addressing": "static"},
                "risk": 20,
                "requires": ["interfaces"],
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
        "firewall": {"filter": [], "nat": []},
        "qos": {"simple_queues": [], "queue_tree": [], "queue_types": []},
    }


class RouterOSQoSRendererTests(unittest.TestCase):
    def test_plan_is_generation_only_and_deterministic(self):
        first = render_routeros_qos(ir=ir_payload(), state=state_payload()).as_dict()
        second = render_routeros_qos(ir=ir_payload(), state=state_payload()).as_dict()
        self.assertEqual(first, second)
        self.assertFalse(first["transport_present"])
        self.assertFalse(first["apply_available"])
        self.assertFalse(first["write_authorized"])
        self.assertFalse(first["default_mangle_generated"])
        self.assertEqual(first["default_classification"], "queue_tree_packet_mark_no_mark")
        self.assertEqual(len(first["plan_sha256"]), 64)

    def test_default_class_uses_no_mark_leaf_without_default_mangle(self):
        plan = render_routeros_qos(ir=ir_payload(), state=state_payload()).as_dict()
        commands = plan["commands"]
        ids = [item["command_id"] for item in commands]
        self.assertFalse(any("mark.wan10g.default" in value or "mark.wan1g.default" in value for value in ids))
        default_leaves = [item for item in commands if item["command_id"].endswith("08.default")]
        self.assertEqual(len(default_leaves), 2)
        for leaf in default_leaves:
            self.assertIn("packet-mark=no-mark", leaf["command"])
            self.assertIn('queue="routercfg-fq-codel"', leaf["command"])

    def test_non_default_dscp_classes_are_marked_and_shaped(self):
        plan = render_routeros_qos(ir=ir_payload(), state=state_payload()).as_dict()
        rendered = "\n".join(item["command"] for item in plan["commands"])
        self.assertIn("dscp=46 packet-mark=no-mark action=mark-packet", rendered)
        self.assertIn('new-packet-mark="routercfg-qos-wan10g-voice"', rendered)
        self.assertIn("priority=1 limit-at=1900000000", rendered)
        self.assertIn('parent="sfp-sfpplus1" max-limit=9500000000', rendered)
        self.assertNotIn("/queue/simple", rendered)

    def test_active_fasttrack_blocks_rendering(self):
        state = state_payload()
        state["firewall"]["filter"] = [{"action": "fasttrack-connection", "disabled": False}]
        with self.assertRaisesRegex(RouterOSQoSRenderError, "FastTrack"):
            render_routeros_qos(ir=ir_payload(), state=state)

    def test_active_simple_queue_blocks_rendering(self):
        state = state_payload()
        state["qos"]["simple_queues"] = [{"name": "legacy-limit", "disabled": False}]
        with self.assertRaisesRegex(RouterOSQoSRenderError, "Simple Queue"):
            render_routeros_qos(ir=ir_payload(), state=state)

    def test_unmanaged_queue_tree_on_wan_blocks_rendering(self):
        state = state_payload()
        state["qos"]["queue_tree"] = [{"name": "legacy-wan-shaper", "parent": "ether1", "disabled": False}]
        with self.assertRaisesRegex(RouterOSQoSRenderError, "unmanaged Queue Tree"):
            render_routeros_qos(ir=ir_payload(), state=state)

    def test_queue_type_discovery_is_mandatory(self):
        state = state_payload()
        del state["qos"]["queue_types"]
        with self.assertRaisesRegex(RouterOSQoSRenderError, "queue-type discovery"):
            render_routeros_qos(ir=ir_payload(), state=state)

    def test_incompatible_reserved_queue_type_blocks_rendering(self):
        state = state_payload()
        state["qos"]["queue_types"] = [{"name": "routercfg-fq-codel", "kind": "pcq"}]
        with self.assertRaisesRegex(RouterOSQoSRenderError, "incompatible queue kind"):
            render_routeros_qos(ir=ir_payload(), state=state)

    def test_limits_must_cover_every_wan_exactly(self):
        ir = ir_payload()
        qos_op = next(item for item in ir["operations"] if item["resource"] == "traffic_policy")
        qos_op["attributes"]["egress_limits_mbps"] = {"wan10g": 9500}
        unsigned = dict(ir)
        unsigned.pop("ir_sha256")
        ir["ir_sha256"] = hashlib.sha256(
            json.dumps(unsigned, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
        ).hexdigest()
        with self.assertRaisesRegex(RouterOSQoSRenderError, "exactly every WAN"):
            render_routeros_qos(ir=ir, state=state_payload())

    def test_tampered_ir_digest_is_rejected(self):
        ir = ir_payload()
        ir["operations"][0]["attributes"]["policy"] = "tampered"
        with self.assertRaisesRegex(RouterOSQoSRenderError, "digest mismatch"):
            render_routeros_qos(ir=ir, state=state_payload())


if __name__ == "__main__":
    unittest.main()
