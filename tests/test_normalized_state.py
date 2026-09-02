import copy
import json
import unittest
from pathlib import Path

from router_configuration.m02_state_engine import StateEngine
from router_configuration.normalized_state import (
    NETWORK_STATE_SCHEMA,
    routeros_to_network_state,
    validate_network_state,
)
from router_configuration.routeros_discovery import normalize_routeros_snapshot


FIXTURE = Path(__file__).parent / "fixtures" / "routeros_readonly_snapshot.json"


class VendorNeutralNetworkStateTests(unittest.TestCase):
    def setUp(self):
        self.raw = json.loads(FIXTURE.read_text(encoding="utf-8"))
        self.routeros_state = normalize_routeros_snapshot(self.raw)

    def test_routeros_maps_to_valid_network_state_v1(self):
        state = routeros_to_network_state(self.routeros_state)
        self.assertEqual(state["schema_version"], NETWORK_STATE_SCHEMA)
        result = validate_network_state(state)
        self.assertTrue(result.ok, result.errors)
        self.assertEqual(state["device"]["vendor"], "mikrotik")
        self.assertEqual(state["device"]["model"], "CCR2116-12G-4S+")
        self.assertEqual(state["device"]["firmware_version"], "7.24.1 (stable)")
        self.assertEqual(state["source"]["vendor_schema"], "routeros-state/1")

    def test_core_state_excludes_private_and_preshared_keys(self):
        state = routeros_to_network_state(self.routeros_state)
        rendered = json.dumps(state, sort_keys=True)
        self.assertNotIn("private-key", rendered)
        self.assertNotIn("private_key", rendered)
        self.assertNotIn("preshared-key", rendered)
        self.assertNotIn("preshared_key", rendered)
        self.assertNotIn("synthetic-private-key", rendered)
        self.assertNotIn("synthetic-psk", rendered)
        self.assertIn("synthetic-public-key", rendered)

    def test_mapping_is_deterministic_when_vendor_record_order_changes(self):
        reordered = copy.deepcopy(self.raw)
        reordered["interfaces"] = list(reversed(reordered["interfaces"]))
        reordered["ip_routes"] = list(reversed(reordered["ip_routes"]))
        first = routeros_to_network_state(self.routeros_state)
        second = routeros_to_network_state(normalize_routeros_snapshot(reordered))
        self.assertEqual(first, second)

    def test_state_engine_is_noop_for_same_normalized_state(self):
        state = routeros_to_network_state(self.routeros_state)
        plan = StateEngine().build_plan(state, copy.deepcopy(state))
        self.assertTrue(plan.is_noop)
        self.assertFalse(StateEngine().has_drift(state, copy.deepcopy(state)))

    def test_interface_semantics_are_vendor_neutral(self):
        state = routeros_to_network_state(self.routeros_state)
        interfaces = {item["name"]: item for item in state["interfaces"]}
        self.assertTrue(interfaces["sfp-sfpplus1"]["enabled"])
        self.assertTrue(interfaces["sfp-sfpplus1"]["operational"])
        self.assertEqual(interfaces["sfp-sfpplus1"]["kind"], "ether")

    def test_unknown_network_state_field_is_rejected(self):
        state = routeros_to_network_state(self.routeros_state)
        state["vendor_command"] = "/ip route add ..."
        result = validate_network_state(state)
        self.assertFalse(result.ok)
        self.assertTrue(any("unknown network-state" in error for error in result.errors))


if __name__ == "__main__":
    unittest.main()
