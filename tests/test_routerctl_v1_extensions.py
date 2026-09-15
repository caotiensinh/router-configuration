import json
import tempfile
import unittest
from contextlib import redirect_stdout
from io import StringIO
from pathlib import Path

from router_configuration.renderer_coverage import (
    RendererCoverageStatus,
    assess_renderer_coverage,
)
from router_configuration.routerctl import main
from router_configuration.routeros_discovery import normalize_routeros_snapshot
from router_configuration.routeros_evidence import build_routeros_discovery_evidence
from router_configuration.v1_extended_ir import V1ExtendedSafeSubsetCompiler


ROOT = Path(__file__).resolve().parents[1]
PROFILE = ROOT / "examples" / "rd-10g-1g" / "deployment-profile.json"
RAW = ROOT / "tests" / "fixtures" / "routeros_readonly_snapshot.json"
PUBLIC_KEY_A = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="
PUBLIC_KEY_B = "AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE="


def _extended_profile():
    profile = json.loads(PROFILE.read_text(encoding="utf-8"))
    profile["topology"]["wans"] = [
        {
            "name": "wan10g",
            "interface": "sfp-sfpplus1",
            "capacity_mbps": 10000,
            "addressing": "static",
            "address": "192.0.2.2/30",
            "enabled": True,
            "routing": {
                "gateway": "192.0.2.1",
                "table": "to-wan10g",
                "failover_distance": 10,
                "health_probe_targets": ["1.1.1.1", "8.8.8.8"],
            },
        },
        {
            "name": "wan1g",
            "interface": "ether1",
            "capacity_mbps": 1000,
            "addressing": "static",
            "address": "198.51.100.2/30",
            "enabled": True,
            "routing": {
                "gateway": "198.51.100.1",
                "table": "to-wan1g",
                "failover_distance": 20,
                "health_probe_targets": ["9.9.9.9", "208.67.222.222"],
            },
        },
    ]
    security = profile["intent"]["security"]
    security["management_sources"] = ["192.168.11.0/24"]
    security["anti_spoofing"] = True
    security["icmp_policy"] = "essential_ipv4"
    security["required_wan_services"] = []
    profile["intent"]["vpn"]["wireguard"] = {
        "enabled": True,
        "secret_ref": "vault://routers/rd-router-01/wireguard-private-key",
        "name": "wg-enterprise",
        "addresses": ["10.250.0.1/24"],
        "listen_port": 51820,
        "mtu": 1420,
        "peers": [
            {
                "name": "branch-a",
                "public_key": PUBLIC_KEY_A,
                "tunnel_address": "10.250.0.2/32",
                "allowed_addresses": ["10.250.0.2/32", "10.40.0.0/24"],
                "routes": ["10.40.0.0/24"],
                "endpoint_address": "198.51.100.10",
                "endpoint_port": 51820,
                "persistent_keepalive": 25,
                "responder": False,
            },
            {
                "name": "branch-b",
                "public_key": PUBLIC_KEY_B,
                "tunnel_address": "10.250.0.3/32",
                "allowed_addresses": ["10.250.0.3/32", "10.50.0.0/24"],
                "routes": ["10.50.0.0/24"],
                "responder": True,
            },
        ],
    }
    profile["intent"]["segmentation"] = {
        "enabled": True,
        "bridge": "br-lan",
        "vlans": [
            {"id": 10, "name": "management"},
            {"id": 20, "name": "users"},
        ],
        "ports": [
            {
                "interface": "sfp-sfpplus2",
                "mode": "trunk",
                "allowed_vlans": [10, 20],
            },
        ],
        "management": {
            "vlan_id": 10,
            "port": "sfp-sfpplus2",
            "address": "10.10.10.1/24",
        },
    }
    profile["intent"]["pbr"] = {
        "enabled": True,
        "strategy": "routing_rules",
        "rules": [
            {
                "name": "users-via-wan1g",
                "source_cidr": "10.20.0.0/24",
                "destination_cidr": "0.0.0.0/0",
                "table": "to-wan1g",
                "action": "lookup",
            }
        ],
    }
    return profile


def _evidence():
    raw = json.loads(RAW.read_text(encoding="utf-8"))
    evidence = build_routeros_discovery_evidence(normalize_routeros_snapshot(raw))
    evidence["render_prerequisites"] = {
        "schema_version": "routeros-render-prerequisites/1",
        "switching": {
            "bridges": [],
            "bridge_ports": [],
            "bridge_vlans": [],
            "vlan_interfaces": [],
        },
        "qos": {"queue_types": []},
        "policy_routing": {"rules": []},
        "read_only": True,
        "write_methods_present": False,
    }
    evidence["management_path"] = {
        "ok": True,
        "interface": "ether1",
        "evidence_ref": "tests/fixtures/routeros_readonly_snapshot.json",
    }
    return evidence


class RouterctlV1ExtensionTests(unittest.TestCase):
    def test_routeros_render_covers_planned_v1_without_enabling_execution(self):
        profile = _extended_profile()
        ir = V1ExtendedSafeSubsetCompiler().compile(profile).as_dict()
        evidence = _evidence()

        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            profile_path = root / "profile.json"
            ir_path = root / "ir.json"
            evidence_path = root / "evidence.json"
            output_path = root / "render.json"
            script_path = root / "render.rsc"
            profile_path.write_text(json.dumps(profile), encoding="utf-8")
            ir_path.write_text(json.dumps(ir), encoding="utf-8")
            evidence_path.write_text(json.dumps(evidence), encoding="utf-8")

            stdout = StringIO()
            with redirect_stdout(stdout):
                rc = main(
                    [
                        "routeros-render",
                        "--profile",
                        str(profile_path),
                        "--ir",
                        str(ir_path),
                        "--evidence",
                        str(evidence_path),
                        "--output",
                        str(output_path),
                        "--script-output",
                        str(script_path),
                    ]
                )

            self.assertEqual(rc, 0, stdout.getvalue())
            summary = json.loads(stdout.getvalue())
            self.assertTrue(summary["ok"])
            self.assertFalse(summary["transport_present"])
            self.assertFalse(summary["apply_available"])
            self.assertFalse(summary["write_authorized"])

            payload = json.loads(output_path.read_text(encoding="utf-8"))
            plan = payload["render_plan"]
            extensions = plan["state_bound_extensions"]
            self.assertGreater(extensions["vlan_segmentation"]["command_count"], 0)
            self.assertGreater(extensions["policy_routing"]["command_count"], 0)
            for extension_name in (
                "capacity_weighted_pcc",
                "vlan_segmentation",
                "policy_routing",
            ):
                extension = extensions[extension_name]
                self.assertGreater(extension["command_count"], 0)
                self.assertFalse(extension["transport_present"])
                self.assertFalse(extension["apply_available"])
                self.assertFalse(extension["write_authorized"])

            coverage = assess_renderer_coverage(ir=ir, render_plan=plan)
            by_id = {item.operation_id: item for item in coverage.operations}
            self.assertTrue(coverage.renderer_complete, coverage.as_dict())
            self.assertTrue(coverage.execution_deferred)
            self.assertFalse(
                any(
                    item.status is RendererCoverageStatus.BLOCKED
                    for item in coverage.operations
                ),
                coverage.as_dict(),
            )
            self.assertIs(
                by_id["switching.vlan.segmentation"].status,
                RendererCoverageStatus.RENDERED,
            )
            self.assertIs(
                by_id["routing.pbr.rules"].status,
                RendererCoverageStatus.RENDERED,
            )
            self.assertIs(
                by_id["vpn.wireguard"].status,
                RendererCoverageStatus.DEFERRED_EXECUTION_BOUNDARY,
            )
            coverage_payload = coverage.as_dict()
            self.assertFalse(coverage_payload["production_writer_available"])
            self.assertFalse(coverage_payload["write_authorized"])

            script = script_path.read_text(encoding="utf-8")
            self.assertIn("vlan-filtering=yes", script)
            self.assertIn("/routing/rule/add", script)
            self.assertNotIn("password", script.lower())
            self.assertNotIn("private-key", script.lower())


if __name__ == "__main__":
    unittest.main()
