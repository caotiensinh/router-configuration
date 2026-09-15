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


def extended_profile():
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


def evidence():
    raw = json.loads(RAW_FIXTURE.read_text(encoding="utf-8"))
    return build_routeros_discovery_evidence(normalize_routeros_snapshot(raw))


class ExtendedIRRenderReadinessTests(unittest.TestCase):
    def test_extended_ir_is_bound_to_same_product_compiler(self):
        profile = extended_profile()
        ir = V1ExtendedSafeSubsetCompiler().compile(profile).as_dict()
        result = assess_render_readiness(profile=profile, ir=ir, evidence=evidence())

        self.assertFalse(
            any("IR digest/profile binding mismatch" in error for error in result.errors),
            result.errors,
        )
        self.assertFalse(
            any("IR operations do not match" in error for error in result.errors),
            result.errors,
        )
        self.assertEqual(result.ir_sha256, ir["ir_sha256"])


if __name__ == "__main__":
    unittest.main()
