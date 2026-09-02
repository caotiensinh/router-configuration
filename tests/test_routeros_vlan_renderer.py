import hashlib
import json
import unittest

from router_configuration.routeros_vlan_renderer import (
    RouterOSVlanRenderError,
    render_routeros_vlan,
)


def ir_payload():
    payload = {
        "schema_version": "config-safe-subset-ir/1",
        "device_id": "router-01",
        "operations": [
            {
                "operation_id": "switching.vlan-segmentation",
                "feature": "segmentation",
                "resource": "vlan_segmentation_policy",
                "attributes": {
                    "enabled": True,
                    "bridge": "bridge-core",
                    "vlans": [
                        {"id": 10, "name": "users"},
                        {"id": 99, "name": "management"},
                    ],
                    "ports": [
                        {
                            "interface": "ether2",
                            "mode": "access",
                            "access_vlan": 10,
                            "frame_types": "admit-only-untagged-and-priority-tagged",
                            "ingress_filtering": True,
                        },
                        {
                            "interface": "ether3",
                            "mode": "access",
                            "access_vlan": 99,
                            "frame_types": "admit-only-untagged-and-priority-tagged",
                            "ingress_filtering": True,
                        },
                        {
                            "interface": "sfp-sfpplus2",
                            "mode": "trunk",
                            "allowed_vlans": [10, 99],
                            "frame_types": "admit-only-vlan-tagged",
                            "ingress_filtering": True,
                        },
                    ],
                    "management": {
                        "vlan_id": 99,
                        "port": "ether3",
                        "address": "192.168.99.1/24",
                    },
                    "activation_order": "management_first_vlan_filtering_last",
                    "vlan_filtering": True,
                },
                "risk": 30,
                "requires": ["interfaces", "management_path"],
                "secret_references": [],
            }
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
        "interfaces": [
            {"name": "ether1"},
            {"name": "ether2"},
            {"name": "ether3"},
            {"name": "sfp-sfpplus2"},
        ],
        "ip_addresses": [{"address": "10.0.2.15/24", "interface": "ether1"}],
    }


def prerequisites():
    return {
        "schema_version": "routeros-render-prerequisites/1",
        "switching": {
            "bridges": [],
            "bridge_ports": [],
            "bridge_vlans": [],
            "vlan_interfaces": [],
        },
    }


def management_path(interface="ether1", ok=True):
    return {
        "ok": ok,
        "interface": interface,
        "evidence_ref": "evidence/current-management.json",
    }


class RouterOSVlanRendererTests(unittest.TestCase):
    def test_generation_only_plan_keeps_activation_last(self):
        plan = render_routeros_vlan(
            ir=ir_payload(),
            state=state_payload(),
            prerequisites=prerequisites(),
            management_path=management_path(),
        ).as_dict()
        self.assertFalse(plan["transport_present"])
        self.assertFalse(plan["apply_available"])
        self.assertFalse(plan["write_authorized"])
        self.assertEqual(plan["activation_policy"], "management_first_vlan_filtering_last")
        self.assertEqual(plan["commands"][-1]["command_id"], "vlan.99.activate-filtering")
        self.assertIn("vlan-filtering=yes", plan["commands"][-1]["command"])
        self.assertEqual(plan["commands"][-1]["risk"], 40)

    def test_management_interface_and_address_exist_before_activation(self):
        plan = render_routeros_vlan(
            ir=ir_payload(),
            state=state_payload(),
            prerequisites=prerequisites(),
            management_path=management_path(),
        ).as_dict()
        ids = [item["command_id"] for item in plan["commands"]]
        self.assertLess(ids.index("vlan.30.management-interface"), ids.index("vlan.99.activate-filtering"))
        self.assertLess(ids.index("vlan.31.management-address"), ids.index("vlan.99.activate-filtering"))
        rendered = "\n".join(item["command"] for item in plan["commands"])
        self.assertIn('tagged="bridge-core,sfp-sfpplus2"', rendered)
        self.assertIn('untagged="ether3"', rendered)

    def test_current_management_must_be_out_of_band(self):
        with self.assertRaisesRegex(RouterOSVlanRenderError, "out-of-band"):
            render_routeros_vlan(
                ir=ir_payload(),
                state=state_payload(),
                prerequisites=prerequisites(),
                management_path=management_path(interface="ether3"),
            )

    def test_existing_target_bridge_is_rejected(self):
        prereq = prerequisites()
        prereq["switching"]["bridges"] = [{"name": "bridge-core"}]
        with self.assertRaisesRegex(RouterOSVlanRenderError, "existing target bridge"):
            render_routeros_vlan(
                ir=ir_payload(),
                state=state_payload(),
                prerequisites=prereq,
                management_path=management_path(),
            )

    def test_existing_bridge_port_membership_is_rejected(self):
        prereq = prerequisites()
        prereq["switching"]["bridge_ports"] = [
            {"interface": "ether2", "bridge": "legacy-bridge"}
        ]
        with self.assertRaisesRegex(RouterOSVlanRenderError, "already belong to a bridge"):
            render_routeros_vlan(
                ir=ir_payload(),
                state=state_payload(),
                prerequisites=prereq,
                management_path=management_path(),
            )

    def test_management_network_overlap_is_rejected(self):
        state = state_payload()
        state["ip_addresses"].append({"address": "192.168.99.10/24", "interface": "ether4"})
        with self.assertRaisesRegex(RouterOSVlanRenderError, "overlaps existing router address"):
            render_routeros_vlan(
                ir=ir_payload(),
                state=state,
                prerequisites=prerequisites(),
                management_path=management_path(),
            )

    def test_missing_live_port_is_rejected(self):
        state = state_payload()
        state["interfaces"] = [row for row in state["interfaces"] if row["name"] != "ether3"]
        with self.assertRaisesRegex(RouterOSVlanRenderError, "not present in live state"):
            render_routeros_vlan(
                ir=ir_payload(),
                state=state,
                prerequisites=prerequisites(),
                management_path=management_path(),
            )

    def test_tampered_ir_is_rejected(self):
        ir = ir_payload()
        ir["operations"][0]["attributes"]["activation_order"] = "unsafe"
        with self.assertRaisesRegex(RouterOSVlanRenderError, "digest mismatch"):
            render_routeros_vlan(
                ir=ir,
                state=state_payload(),
                prerequisites=prerequisites(),
                management_path=management_path(),
            )


if __name__ == "__main__":
    unittest.main()
