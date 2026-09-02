import copy
import json
import unittest
from collections import Counter
from pathlib import Path

from router_configuration.routeros_pcc_plan import assess_routeros_pcc
from router_configuration.safe_subset_ir import SafeSubsetCompiler


ROOT = Path(__file__).resolve().parents[1]
PROFILE_PATH = ROOT / "examples" / "rd-10g-1g" / "deployment-profile.json"
STATE_PATH = ROOT / "tests" / "fixtures" / "routeros_normalized_golden.json"


def profile():
    data = json.loads(PROFILE_PATH.read_text(encoding="utf-8"))
    data["topology"]["wans"] = [
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
    return data


def ir():
    return SafeSubsetCompiler().compile(profile()).as_dict()


def state():
    return json.loads(STATE_PATH.read_text(encoding="utf-8"))


class RouterOSPccPlanTests(unittest.TestCase):
    def test_10g_1g_plan_freezes_safe_mangle_invariants(self):
        result = assess_routeros_pcc(ir=ir(), state=state())
        self.assertTrue(result.ok, result.errors)
        payload = result.as_dict()
        spec = payload["spec"]
        self.assertEqual(spec["classifier"], "both-addresses-and-ports")
        self.assertEqual(spec["ingress_interface_list"], "routercfg-CORE")
        self.assertTrue(spec["exclude_local_destinations"])
        self.assertEqual(spec["connection_state"], "new")
        self.assertTrue(spec["require_unmarked_connection"])
        self.assertFalse(spec["fasttrack_compatible"])
        self.assertFalse(spec["write_authorized"])
        self.assertFalse(payload["write_authorized"])
        self.assertEqual(len(spec["buckets"]), 11)
        self.assertEqual(
            Counter(bucket["wan_name"] for bucket in spec["buckets"]),
            {"wan10g": 10, "wan1g": 1},
        )
        self.assertEqual(
            {bucket["classifier"] for bucket in spec["buckets"]},
            {f"11/{index}" for index in range(11)},
        )

    def test_active_fasttrack_blocks_pcc_render_readiness(self):
        current = state()
        current = copy.deepcopy(current)
        current["firewall"]["filter"].append(
            {
                ".id": "*FT1",
                "chain": "forward",
                "action": "fasttrack-connection",
                "disabled": False,
            }
        )
        result = assess_routeros_pcc(ir=ir(), state=current)
        self.assertFalse(result.ok)
        self.assertTrue(any("FastTrack" in error and "*FT1" in error for error in result.errors))
        self.assertIsNone(result.spec)

    def test_disabled_fasttrack_does_not_block(self):
        current = state()
        current = copy.deepcopy(current)
        current["firewall"]["filter"].append(
            {
                ".id": "*FT1",
                "chain": "forward",
                "action": "fasttrack-connection",
                "disabled": True,
            }
        )
        result = assess_routeros_pcc(ir=ir(), state=current)
        self.assertTrue(result.ok, result.errors)

    def test_command_bearing_ir_is_rejected(self):
        payload = ir()
        payload["vendor_commands_present"] = True
        result = assess_routeros_pcc(ir=payload, state=state())
        self.assertFalse(result.ok)
        self.assertTrue(any("command-free" in error for error in result.errors))


if __name__ == "__main__":
    unittest.main()
