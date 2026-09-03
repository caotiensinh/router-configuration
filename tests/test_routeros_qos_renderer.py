import hashlib
import json
import unittest
from pathlib import Path

from router_configuration.routeros_qos_renderer import (
    RouterOSQoSRenderError,
    render_routeros_qos,
)
from router_configuration.safe_subset_ir import SafeSubsetCompiler


ROOT = Path(__file__).resolve().parents[1]
PROFILE = ROOT / "examples" / "rd-10g-1g" / "deployment-profile.json"


def load_profile():
    return json.loads(PROFILE.read_text(encoding="utf-8"))


def compile_ir():
    return SafeSubsetCompiler().compile(load_profile()).as_dict()


def resign_ir(payload):
    payload = json.loads(json.dumps(payload))
    payload.pop("ir_sha256", None)
    canonical = json.dumps(
        payload,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
    ).encode("utf-8")
    payload["ir_sha256"] = hashlib.sha256(canonical).hexdigest()
    return payload


class RouterOSQoSRendererTests(unittest.TestCase):
    def test_reference_policy_renders_global_sibling_fq_codel_for_both_wans(self):
        plan = render_routeros_qos(ir=compile_ir()).as_dict()

        self.assertEqual(plan["schema_version"], "routeros-qos-command-plan/1")
        self.assertEqual(plan["operation_id"], "qos.policy")
        self.assertEqual(plan["policy"], "latency_sensitive_first")
        self.assertEqual(
            plan["strategy"],
            "global_sibling_fq_codel_unmarked_default_marked_priority",
        )
        self.assertEqual(
            plan["queue_type"],
            {"name": "routercfg-qos-fq", "kind": "fq-codel"},
        )
        self.assertEqual(plan["policy_contract"]["latency_dscp"], 46)
        self.assertEqual(plan["policy_contract"]["priority"], 1)
        self.assertEqual(plan["policy_contract"]["reserve_percent"], 10)
        self.assertEqual(
            plan["policy_contract"]["default_classification"],
            "remaining_unmarked",
        )
        self.assertFalse(plan["policy_contract"]["aggregate_shaping_claimed"])
        self.assertFalse(plan["policy_contract"]["bandwidth_guarantee_claimed"])
        self.assertFalse(plan["policy_contract"]["latency_performance_claimed"])
        self.assertFalse(plan["default_traffic_marked"])
        self.assertFalse(plan["transport_present"])
        self.assertFalse(plan["apply_available"])
        self.assertFalse(plan["write_authorized"])
        self.assertFalse(plan["secrets_resolved"])

        targets = {item["name"]: item for item in plan["targets"]}
        self.assertEqual(set(targets), {"wan10g", "wan1g"})
        self.assertEqual(targets["wan10g"]["interface"], "sfp-sfpplus1")
        self.assertEqual(targets["wan10g"]["capacity_mbps"], 10000)
        self.assertEqual(targets["wan10g"]["reserve_mbps"], 1000)
        self.assertEqual(targets["wan1g"]["interface"], "ether1")
        self.assertEqual(targets["wan1g"]["capacity_mbps"], 1000)
        self.assertEqual(targets["wan1g"]["reserve_mbps"], 100)
        self.assertTrue(all("parent_queue" not in target for target in targets.values()))

        commands = plan["commands"]
        self.assertEqual(len(commands), 7)
        self.assertEqual(sum(item["section"] == "queue_type" for item in commands), 1)
        self.assertEqual(sum(item["section"] == "firewall_mangle" for item in commands), 2)
        self.assertEqual(sum(item["section"] == "queue_tree" for item in commands), 4)
        self.assertEqual(len({item["command_id"] for item in commands}), 7)

        mangle = [item["command"] for item in commands if item["section"] == "firewall_mangle"]
        self.assertTrue(all("dscp=46" in command for command in mangle))
        self.assertTrue(all("packet-mark=no-mark" in command for command in mangle))
        self.assertTrue(all("action=mark-packet" in command for command in mangle))
        self.assertTrue(all("passthrough=no" in command for command in mangle))

        queue_commands = [item["command"] for item in commands if item["section"] == "queue_tree"]
        self.assertEqual(sum("packet-mark=no-mark" in command for command in queue_commands), 2)
        self.assertEqual(sum("priority=8" in command for command in queue_commands), 2)
        self.assertEqual(sum("priority=1" in command for command in queue_commands), 2)
        self.assertTrue(all("parent=\"" in command for command in queue_commands))
        self.assertTrue(all("-parent\"" not in command for command in queue_commands))

        command_text = "\n".join(item["command"] for item in commands)
        self.assertNotIn("qos:default", command_text)
        self.assertNotIn("new-packet-mark=\"routercfg-qos-default", command_text)
        self.assertIn("max-limit=10000M", command_text)
        self.assertIn("limit-at=1000M", command_text)
        self.assertIn("max-limit=1000M", command_text)
        self.assertIn("limit-at=100M", command_text)

    def test_renderer_is_deterministic(self):
        payload = compile_ir()
        first = render_routeros_qos(ir=payload).as_dict()
        second = render_routeros_qos(ir=payload).as_dict()
        self.assertEqual(first, second)

    def test_tampered_ir_digest_fails_closed(self):
        payload = compile_ir()
        wan = next(
            item for item in payload["operations"] if item["resource"] == "wan_role"
        )
        wan["attributes"]["capacity_mbps"] = 9999
        with self.assertRaisesRegex(RouterOSQoSRenderError, "digest mismatch"):
            render_routeros_qos(ir=payload)

    def test_unsupported_policy_fails_closed_after_valid_digest(self):
        payload = compile_ir()
        qos = next(
            item for item in payload["operations"] if item["operation_id"] == "qos.policy"
        )
        qos["attributes"]["policy"] = "unknown_policy"
        payload = resign_ir(payload)
        with self.assertRaisesRegex(RouterOSQoSRenderError, "unsupported QoS policy"):
            render_routeros_qos(ir=payload)

    def test_duplicate_wan_interface_fails_closed(self):
        payload = compile_ir()
        wans = [item for item in payload["operations"] if item["resource"] == "wan_role"]
        self.assertEqual(len(wans), 2)
        wans[1]["attributes"]["interface"] = wans[0]["attributes"]["interface"]
        payload = resign_ir(payload)
        with self.assertRaisesRegex(RouterOSQoSRenderError, "duplicate QoS target interface"):
            render_routeros_qos(ir=payload)


if __name__ == "__main__":
    unittest.main()
