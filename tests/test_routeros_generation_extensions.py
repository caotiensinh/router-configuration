import hashlib
import json
import unittest

from router_configuration.routeros_generation_extensions import (
    apply_state_bound_vlan_pbr_extensions,
)
from router_configuration.routeros_pbr_renderer import RouterOSPbrRenderError
from router_configuration.routeros_renderer import RouterOSSafeSubsetRenderer
from router_configuration.routeros_vlan_renderer import RouterOSVlanRenderError


def _signed_ir(*, include_vlan=True, include_pbr=True):
    operations = [
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
    ]
    if include_vlan:
        operations.append(
            {
                "operation_id": "switching.vlan.segmentation",
                "feature": "segmentation",
                "resource": "vlan_segmentation_policy",
                "attributes": {
                    "enabled": True,
                    "bridge": "bridge-core",
                    "vlans": [
                        {"id": 20, "name": "camera"},
                        {"id": 99, "name": "management"},
                    ],
                    "ports": [
                        {
                            "interface": "ether2",
                            "mode": "access",
                            "access_vlan": 20,
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
                            "allowed_vlans": [20, 99],
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
        )
    if include_pbr:
        operations.append(
            {
                "operation_id": "routing.pbr.rules",
                "feature": "pbr",
                "resource": "policy_routing_rules",
                "attributes": {
                    "enabled": True,
                    "strategy": "routing_rules",
                    "mangle_routing_marks": False,
                    "rules": [
                        {
                            "name": "camera-egress",
                            "source_cidr": "192.168.20.0/24",
                            "destination_cidr": "0.0.0.0/0",
                            "in_interface": "vlan20",
                            "table": "to-wan10g",
                            "action": "lookup",
                            "fallback_to_main": True,
                        }
                    ],
                },
                "risk": 30,
                "requires": ["routing"],
                "secret_references": [],
            }
        )
    payload = {
        "schema_version": "config-safe-subset-ir/1",
        "device_id": "router-01",
        "operations": sorted(operations, key=lambda item: item["operation_id"]),
        "vendor_commands_present": False,
        "write_transport_present": False,
    }
    payload["ir_sha256"] = hashlib.sha256(
        json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()
    ).hexdigest()
    return payload


def _evidence():
    return {
        "normalized_state": {
            "interfaces": [
                {"name": "ether1"},
                {"name": "ether2"},
                {"name": "ether3"},
                {"name": "sfp-sfpplus2"},
            ],
            "ip_addresses": [{"address": "10.0.2.15/24", "interface": "ether1"}],
            "routing_tables": [{"name": "main"}],
        },
        "render_prerequisites": {
            "schema_version": "routeros-render-prerequisites/1",
            "switching": {
                "bridges": [],
                "bridge_ports": [],
                "bridge_vlans": [],
                "vlan_interfaces": [],
            },
            "policy_routing": {"rules": []},
        },
        "management_path": {
            "ok": True,
            "interface": "ether1",
            "evidence_ref": "evidence/current-management.json",
        },
    }


class RouterOSGenerationExtensionsTests(unittest.TestCase):
    def test_vlan_and_pbr_merge_remove_only_their_blockers(self):
        ir = _signed_ir()
        base = RouterOSSafeSubsetRenderer().render(ir).as_dict()
        result = apply_state_bound_vlan_pbr_extensions(
            base_plan=base,
            ir=ir,
            evidence=_evidence(),
        )
        blockers = {
            item["operation_id"] for item in result["blocked_operations"]
        }
        self.assertNotIn("switching.vlan.segmentation", blockers)
        self.assertNotIn("routing.pbr.rules", blockers)
        self.assertIn("security.baseline", blockers)
        extensions = result["state_bound_extensions"]
        self.assertIn("vlan_segmentation", extensions)
        self.assertIn("policy_routing", extensions)
        rendered = "\n".join(item["command"] for item in result["commands"])
        self.assertIn("vlan-filtering=yes", rendered)
        self.assertIn("/routing/rule/add", rendered)
        self.assertFalse(result["transport_present"])
        self.assertFalse(result["apply_available"])
        self.assertFalse(result["write_authorized"])

    def test_missing_management_path_fails_closed_for_vlan(self):
        ir = _signed_ir(include_pbr=False)
        evidence = _evidence()
        evidence.pop("management_path")
        with self.assertRaisesRegex(RouterOSVlanRenderError, "management_path"):
            apply_state_bound_vlan_pbr_extensions(
                base_plan=RouterOSSafeSubsetRenderer().render(ir).as_dict(),
                ir=ir,
                evidence=evidence,
            )

    def test_unmanaged_routing_rules_fail_closed_for_pbr(self):
        ir = _signed_ir(include_vlan=False)
        evidence = _evidence()
        evidence["render_prerequisites"]["policy_routing"]["rules"] = [
            {".id": "*1", "disabled": False}
        ]
        with self.assertRaisesRegex(RouterOSPbrRenderError, "unmanaged routing rules"):
            apply_state_bound_vlan_pbr_extensions(
                base_plan=RouterOSSafeSubsetRenderer().render(ir).as_dict(),
                ir=ir,
                evidence=evidence,
            )

    def test_no_optional_intent_is_noop(self):
        ir = _signed_ir(include_vlan=False, include_pbr=False)
        base = RouterOSSafeSubsetRenderer().render(ir).as_dict()
        result = apply_state_bound_vlan_pbr_extensions(
            base_plan=base,
            ir=ir,
            evidence={},
        )
        self.assertEqual(result, base)


if __name__ == "__main__":
    unittest.main()
