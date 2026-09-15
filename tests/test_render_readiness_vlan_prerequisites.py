import json
import unittest
from pathlib import Path

from router_configuration.render_readiness import assess_render_readiness
from router_configuration.routeros_discovery import normalize_routeros_snapshot
from router_configuration.routeros_evidence import build_routeros_discovery_evidence
from router_configuration.v1_extended_ir import V1ExtendedSafeSubsetCompiler


ROOT = Path(__file__).resolve().parents[1]
PROFILE_PATH = ROOT / "examples" / "rd-10g-1g" / "deployment-profile.json"
RAW_FIXTURE = ROOT / "tests" / "fixtures" / "routeros_readonly_snapshot.json"


def vlan_profile():
    profile = json.loads(PROFILE_PATH.read_text(encoding="utf-8"))
    profile["intent"]["segmentation"] = {
        "enabled": True,
        "bridge": "br-lan",
        "vlans": [
            {"id": 10, "name": "management"},
            {"id": 20, "name": "users"},
        ],
        "ports": [
            {
                "interface": "ether5",
                "mode": "access",
                "access_vlan": 20,
            },
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
    return profile


def discovery_evidence():
    raw = json.loads(RAW_FIXTURE.read_text(encoding="utf-8"))
    return build_routeros_discovery_evidence(normalize_routeros_snapshot(raw))


def empty_render_prerequisites():
    return {
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


class VlanRenderReadinessPrerequisiteTests(unittest.TestCase):
    def test_explicit_switching_and_ip_address_evidence_satisfy_vlan_requirements(self):
        profile = vlan_profile()
        ir = V1ExtendedSafeSubsetCompiler().compile(profile).as_dict()
        evidence = discovery_evidence()
        evidence["render_prerequisites"] = empty_render_prerequisites()

        result = assess_render_readiness(profile=profile, ir=ir, evidence=evidence)
        relevant = [
            error
            for error in result.errors
            if "switching" in error or "ip_addresses" in error
        ]
        self.assertEqual(relevant, [], result.errors)

    def test_missing_switching_prerequisites_fail_closed(self):
        profile = vlan_profile()
        ir = V1ExtendedSafeSubsetCompiler().compile(profile).as_dict()
        result = assess_render_readiness(
            profile=profile,
            ir=ir,
            evidence=discovery_evidence(),
        )
        self.assertTrue(
            any("required capability 'switching' is unavailable" in error for error in result.errors),
            result.errors,
        )


if __name__ == "__main__":
    unittest.main()
