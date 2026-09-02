import copy
import hashlib
import json
import unittest
from pathlib import Path

from router_configuration.routeros_firewall_renderer import (
    RouterOSFirewallRenderError,
    render_routeros_firewall,
)
from router_configuration.safe_subset_ir import IntentOperation, IntentRisk, SafeSubsetIR


ROOT = Path(__file__).resolve().parents[1]


def firewall_ir(*, services=None):
    if services is None:
        services = [
            {
                "name": "explicit-telemetry",
                "protocol": "tcp",
                "dst_port": 9443,
                "source_cidrs": ["198.51.100.10/32"],
            }
        ]
    return SafeSubsetIR(
        device_id="chr-firewall-lab",
        operations=(
            IntentOperation(
                operation_id="topology.wan.wan-a",
                feature="topology",
                resource="wan_role",
                attributes={"name": "wan-a", "interface": "ether2", "capacity_mbps": 1000},
                risk=IntentRisk.MEDIUM,
                requires=("interfaces",),
            ),
            IntentOperation(
                operation_id="topology.core",
                feature="topology",
                resource="core_uplink_role",
                attributes={"interface": "ether3", "capacity_mbps": 1000},
                risk=IntentRisk.MEDIUM,
                requires=("interfaces",),
            ),
            IntentOperation(
                operation_id="security.baseline",
                feature="security",
                resource="firewall_baseline",
                attributes={
                    "profile": "enterprise_baseline",
                    "wan_input_default": "deny",
                    "management_from_wan": False,
                    "management_sources": ["10.10.10.0/24", "10.10.20.9/32"],
                    "anti_spoofing": True,
                    "icmp_policy": "essential_ipv4",
                    "required_wan_services": services,
                },
                risk=IntentRisk.HIGH,
                requires=("firewall", "nat", "management_path"),
            ),
        ),
    ).as_dict()


def resign(payload):
    unsigned = copy.deepcopy(payload)
    unsigned.pop("ir_sha256", None)
    payload["ir_sha256"] = hashlib.sha256(
        json.dumps(
            unsigned,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=False,
        ).encode("utf-8")
    ).hexdigest()
    return payload


class RouterOSFirewallRendererTests(unittest.TestCase):
    def test_enterprise_baseline_is_deterministic_generation_only(self):
        first = render_routeros_firewall(ir=firewall_ir()).as_dict()
        second = render_routeros_firewall(ir=firewall_ir()).as_dict()
        self.assertEqual(first, second)
        self.assertEqual(first["schema_version"], "routeros-firewall-command-plan/1")
        self.assertEqual(first["scope"], "generation_only")
        self.assertEqual(first["managed_icmp_chain"], "routercfg-icmp")
        self.assertEqual(first["icmp_policy"], "essential_ipv4")
        self.assertFalse(first["transport_present"])
        self.assertFalse(first["apply_available"])
        self.assertFalse(first["write_authorized"])
        self.assertEqual(first["required_interface_lists"], ["routercfg-WAN", "routercfg-CORE"])
        self.assertEqual(first["management_sources"], ["10.10.10.0/24", "10.10.20.9/32"])

        ids = [item["command_id"] for item in first["commands"]]
        self.assertEqual(ids, sorted(ids))
        self.assertEqual(ids[0], "firewall.00.stage-guard")
        self.assertEqual(ids[-1], "firewall.99.remove-stage-guard")

    def test_rule_set_contains_required_enterprise_input_controls(self):
        plan = render_routeros_firewall(ir=firewall_ir()).as_dict()
        source = "\n".join(item["command"] for item in plan["commands"])
        for required in (
            "connection-state=established,related",
            "action=drop connection-state=invalid",
            'action=jump protocol=icmp jump-target="routercfg-icmp"',
            'in-interface-list="routercfg-WAN" src-address-list="routercfg-MGMT-SOURCES"',
            'in-interface-list="routercfg-CORE" src-address-list="routercfg-MGMT-SOURCES"',
            'in-interface-list="routercfg-WAN" protocol=tcp dst-port=9443',
            "routercfg:managed:fw:chain:090-wan-default-deny",
            "routercfg:managed:fw:chain:099-input-default-deny",
            'jump-target="routercfg-input"',
        ):
            self.assertIn(required, source)
        self.assertNotIn("management_from_wan", source)
        self.assertNotIn("0.0.0.0/0", source)

    def test_essential_ipv4_icmp_chain_is_bounded_and_drops_other_types(self):
        plan = render_routeros_firewall(ir=firewall_ir()).as_dict()
        source = "\n".join(item["command"] for item in plan["commands"])
        for icmp_options in ("0:0", "3:0", "3:1", "3:4", "8:0", "11:0", "12:0"):
            self.assertIn(f"icmp-options={icmp_options}", source)
        self.assertIn("routercfg:managed:fw:icmp:099-drop-other", source)
        self.assertNotIn(
            'action=accept protocol=icmp comment="routercfg:managed:fw:chain:030-essential-icmp"',
            source,
        )

    def test_staging_uses_find_derived_anchor_not_unstable_item_number(self):
        plan = render_routeros_firewall(ir=firewall_ir()).as_dict()
        source = "\n".join(item["command"] for item in plan["commands"])
        self.assertIn('[:pick [/ip/firewall/filter/find where chain=input] 0]', source)
        self.assertIn("place-before=$first", source)
        self.assertIn("place-before=$guard", source)
        self.assertNotIn("place-before=0", source)
        self.assertIn("routercfg firewall staging guard missing", source)

    def test_explicit_empty_wan_service_list_is_allowed(self):
        plan = render_routeros_firewall(ir=firewall_ir(services=[])).as_dict()
        self.assertEqual(plan["required_wan_services"], [])
        source = "\n".join(item["command"] for item in plan["commands"])
        self.assertNotIn("routercfg-WAN-SVC-001", source)
        self.assertIn("090-wan-default-deny", source)

    def test_missing_management_sources_or_wan_service_facts_fail_closed(self):
        for field, expected in (
            ("management_sources", "management_sources"),
            ("required_wan_services", "required_wan_services"),
        ):
            payload = firewall_ir()
            operation = next(item for item in payload["operations"] if item["resource"] == "firewall_baseline")
            operation["attributes"].pop(field)
            resign(payload)
            with self.assertRaisesRegex(RouterOSFirewallRenderError, expected):
                render_routeros_firewall(ir=payload)

    def test_management_from_wan_and_unbounded_sources_are_rejected(self):
        payload = firewall_ir()
        operation = next(item for item in payload["operations"] if item["resource"] == "firewall_baseline")
        operation["attributes"]["management_from_wan"] = True
        resign(payload)
        with self.assertRaisesRegex(RouterOSFirewallRenderError, "management_from_wan"):
            render_routeros_firewall(ir=payload)

        payload = firewall_ir()
        operation = next(item for item in payload["operations"] if item["resource"] == "firewall_baseline")
        operation["attributes"]["management_sources"] = ["0.0.0.0/0"]
        resign(payload)
        with self.assertRaisesRegex(RouterOSFirewallRenderError, "bounded IPv4 CIDR"):
            render_routeros_firewall(ir=payload)

    def test_service_name_is_metadata_only_not_routeros_identifier(self):
        payload = firewall_ir(
            services=[
                {
                    "name": 'telemetry"; /system/reboot',
                    "protocol": "udp",
                    "dst_port": 5514,
                    "source_cidrs": ["203.0.113.40/32"],
                }
            ]
        )
        plan = render_routeros_firewall(ir=payload).as_dict()
        source = "\n".join(item["command"] for item in plan["commands"])
        self.assertNotIn("/system/reboot", source)
        self.assertEqual(plan["required_wan_services"][0]["name"], 'telemetry"; /system/reboot')

    def test_tampered_ir_digest_is_rejected(self):
        payload = firewall_ir()
        payload["operations"][0]["attributes"]["interface"] = "ether99"
        with self.assertRaisesRegex(RouterOSFirewallRenderError, "digest mismatch"):
            render_routeros_firewall(ir=payload)

    def test_renderer_source_has_no_transport_or_secret_resolution(self):
        source = (
            ROOT / "src" / "router_configuration" / "routeros_firewall_renderer.py"
        ).read_text(encoding="utf-8")
        for forbidden in (
            "urllib.request",
            "requests.",
            "http.client",
            "paramiko",
            "socket.",
            "subprocess",
            "private-key",
            "password",
            "def apply(",
            "def execute(",
        ):
            self.assertNotIn(forbidden, source)


if __name__ == "__main__":
    unittest.main()
