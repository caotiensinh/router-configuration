import copy
import json
import unittest
from pathlib import Path

from router_configuration.render_readiness import assess_render_readiness
from router_configuration.routeros_discovery import normalize_routeros_snapshot
from router_configuration.routeros_evidence import build_routeros_discovery_evidence
from router_configuration.safe_subset_ir import SafeSubsetCompiler


ROOT = Path(__file__).resolve().parents[1]
PROFILE_PATH = ROOT / "examples" / "rd-10g-1g" / "deployment-profile.json"
RAW_FIXTURE = ROOT / "tests" / "fixtures" / "routeros_readonly_snapshot.json"


def explicit_failover_profile():
    profile = json.loads(PROFILE_PATH.read_text(encoding="utf-8"))
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
    return profile


def evidence_with_routing_tables(extra_tables=()):
    raw = json.loads(RAW_FIXTURE.read_text(encoding="utf-8"))
    state = normalize_routeros_snapshot(raw)
    state = copy.deepcopy(state)
    state["routing_tables"].extend(copy.deepcopy(list(extra_tables)))
    return build_routeros_discovery_evidence(state)


class RenderReadinessRoutingTableSafetyTests(unittest.TestCase):
    def evaluate(self, extra_tables=()):
        profile = explicit_failover_profile()
        ir = SafeSubsetCompiler().compile(profile).as_dict()
        return assess_render_readiness(
            profile=profile,
            ir=ir,
            evidence=evidence_with_routing_tables(extra_tables),
        )

    def test_missing_dedicated_tables_may_be_created_by_renderer(self):
        result = self.evaluate()
        self.assertTrue(result.ok, result.errors)

    def test_existing_fib_enabled_tables_are_accepted(self):
        result = self.evaluate(
            (
                {".id": "*T2", "name": "to-wan10g", "fib": True},
                {".id": "*T3", "name": "to-wan1g", "fib": "yes"},
            )
        )
        self.assertTrue(result.ok, result.errors)

    def test_existing_non_fib_table_is_blocking(self):
        result = self.evaluate(
            ({".id": "*T2", "name": "to-wan10g", "fib": False},)
        )
        self.assertFalse(result.ok)
        self.assertTrue(
            any(
                "to-wan10g" in error and "not FIB-enabled" in error
                for error in result.errors
            ),
            result.errors,
        )


if __name__ == "__main__":
    unittest.main()
