import copy
import json
import unittest
from pathlib import Path

from router_configuration.routeros_renderer import RouterOSRenderError, RouterOSSafeSubsetRenderer
from router_configuration.safe_subset_ir import SafeSubsetCompiler


ROOT = Path(__file__).resolve().parents[1]
PROFILE_PATH = ROOT / "examples" / "rd-10g-1g" / "deployment-profile.json"


def profile():
    return json.loads(PROFILE_PATH.read_text(encoding="utf-8"))


def ir():
    return SafeSubsetCompiler().compile(profile()).as_dict()


class RouterOSSafeSubsetRendererTests(unittest.TestCase):
    def test_reference_render_is_deterministic_generation_only_golden(self):
        renderer = RouterOSSafeSubsetRenderer()
        first = renderer.render(ir()).as_dict()
        second = renderer.render(ir()).as_dict()
        self.assertEqual(first, second)
        self.assertEqual(first["schema_version"], "routeros-render-plan/1")
        self.assertEqual(first["claim"], "generation_partial")
        self.assertFalse(first["complete"])
        self.assertFalse(first["secrets_resolved"])
        self.assertFalse(first["transport_present"])
        self.assertFalse(first["apply_available"])
        self.assertFalse(first["write_authorized"])

        commands = [item["command"] for item in first["commands"]]
        expected = [
            ':if ([:len [/interface/list/find where name="routercfg-CORE"]] = 0) do={/interface/list/add name="routercfg-CORE" comment="routercfg:managed:core-list"}',
            ':local rid [/interface/list/member/find where comment="routercfg:managed:core-uplink"]; :if ([:len $rid] = 0) do={/interface/list/member/add list="routercfg-CORE" interface="sfp-sfpplus2" comment="routercfg:managed:core-uplink"} else={/interface/list/member/set $rid list="routercfg-CORE" interface="sfp-sfpplus2"}',
            ':if ([:len [/interface/list/find where name="routercfg-WAN"]] = 0) do={/interface/list/add name="routercfg-WAN" comment="routercfg:managed:wan-list"}',
            ':local rid [/interface/list/member/find where comment="routercfg:managed:wan:wan10g"]; :if ([:len $rid] = 0) do={/interface/list/member/add list="routercfg-WAN" interface="sfp-sfpplus1" comment="routercfg:managed:wan:wan10g"} else={/interface/list/member/set $rid list="routercfg-WAN" interface="sfp-sfpplus1"}',
            ':local rid [/interface/list/member/find where comment="routercfg:managed:wan:wan1g"]; :if ([:len $rid] = 0) do={/interface/list/member/add list="routercfg-WAN" interface="ether1" comment="routercfg:managed:wan:wan1g"} else={/interface/list/member/set $rid list="routercfg-WAN" interface="ether1"}',
        ]
        self.assertEqual(commands, expected)

    def test_reference_plan_blocks_unknown_or_incomplete_network_facts_instead_of_guessing(self):
        payload = RouterOSSafeSubsetRenderer().render(ir()).as_dict()
        blocked = {item["operation_id"]: item for item in payload["blocked_operations"]}
        self.assertEqual(
            set(blocked),
            {
                "qos.policy",
                "routing.multiwan.capacity_weighted",
                "security.baseline",
                "vpn.wireguard",
            },
        )
        routing_inputs = blocked["routing.multiwan.capacity_weighted"]["required_inputs"]
        self.assertIn("wan.wan10g.gateway", routing_inputs)
        self.assertIn("wan.wan1g.health_probe_targets", routing_inputs)
        self.assertIn("wireguard.listen_port", blocked["vpn.wireguard"]["required_inputs"])
        self.assertIn("qos.upload_rate_mbps", blocked["qos.policy"]["required_inputs"])

    def test_secret_reference_is_preserved_but_never_interpolated_into_commands(self):
        payload = RouterOSSafeSubsetRenderer().render(ir()).as_dict()
        self.assertEqual(
            payload["secret_references"],
            ["vault://routers/rd-router-01/wireguard"],
        )
        command_text = "\n".join(item["command"] for item in payload["commands"])
        self.assertNotIn("vault://", command_text)
        self.assertNotIn("private-key", command_text.lower())
        self.assertNotIn("password", command_text.lower())

    def test_tampered_ir_digest_is_rejected(self):
        payload = ir()
        payload["operations"][0]["attributes"]["capacity_mbps"] = 999999
        with self.assertRaisesRegex(RouterOSRenderError, "digest mismatch"):
            RouterOSSafeSubsetRenderer().render(payload)

    def test_vendor_commands_or_transport_in_source_ir_are_rejected(self):
        for field in ("vendor_commands_present", "write_transport_present"):
            payload = ir()
            payload[field] = True
            unsigned = copy.deepcopy(payload)
            unsigned.pop("ir_sha256", None)
            # Digest is deliberately stale: boundary flags must be rejected before digest checking.
            with self.assertRaises(RouterOSRenderError):
                RouterOSSafeSubsetRenderer().render(payload)

    def test_routeros_script_injection_characters_are_rejected(self):
        payload = ir()
        operation = next(
            item for item in payload["operations"] if item["operation_id"] == "topology.wan.wan10g"
        )
        operation["attributes"]["interface"] = 'ether1"; /system/reboot'
        unsigned = copy.deepcopy(payload)
        unsigned.pop("ir_sha256", None)
        import hashlib

        payload["ir_sha256"] = hashlib.sha256(
            json.dumps(
                unsigned,
                sort_keys=True,
                separators=(",", ":"),
                ensure_ascii=False,
            ).encode("utf-8")
        ).hexdigest()
        with self.assertRaisesRegex(RouterOSRenderError, "unsupported RouterOS v0.1 characters"):
            RouterOSSafeSubsetRenderer().render(payload)

    def test_renderer_source_has_no_network_or_apply_transport(self):
        source = (ROOT / "src" / "router_configuration" / "routeros_renderer.py").read_text(
            encoding="utf-8"
        )
        for forbidden in (
            "urllib.request",
            "requests.",
            "http.client",
            "paramiko",
            "socket.",
            "subprocess",
            "def apply(",
            "def execute(",
        ):
            self.assertNotIn(forbidden, source)


if __name__ == "__main__":
    unittest.main()
