import unittest
from dataclasses import replace

from router_configuration.vendors.cisco.router_state import normalize_router_state
from router_configuration.vendors.cisco.router_state_integrity import (
    CiscoRouterStateIntegrityError,
    verify_router_state_integrity,
)

MODULES = {"Cisco-IOS-XE-interfaces-oper", "ietf-routing"}
SCHEMA_DIGEST = "a" * 64


def normalized_state():
    return normalize_router_state(
        model="C8000V",
        iosxe_version="17.18.1a",
        schema_inventory_digest_sha256=SCHEMA_DIGEST,
        observed_modules=MODULES,
        interface_records=[
            {
                "name": "GigabitEthernet1",
                "vrf": "default",
                "admin-status": "if-state-up",
                "oper-status": "if-oper-state-ready",
                "ipv4": "192.0.2.10",
                "ipv4-subnet-mask": "255.255.255.0",
                "ipv6-addrs": ["2001:db8::10"],
            }
        ],
        route_records=[
            {
                "destination-prefix": "0.0.0.0/0",
                "source-protocol": "static",
                "route-preference": 1,
                "metric": 10,
                "next-hop": {"outgoing-interface": "GigabitEthernet1", "next-hop-address": "192.0.2.1"},
                "active": True,
            }
        ],
    )


class CiscoRouterStateIntegrityTests(unittest.TestCase):
    def test_normalized_state_integrity_is_deterministic_and_non_promoting(self):
        state = normalized_state()
        first = verify_router_state_integrity(state)
        second = verify_router_state_integrity(state)
        self.assertEqual(first, second)
        self.assertTrue(first["normalized_state_integrity_valid"])
        self.assertEqual(first["interface_count"], 1)
        self.assertEqual(first["route_count"], 1)
        self.assertFalse(first["live_state_observed"])
        self.assertFalse(first["repository_c05_complete"])
        self.assertEqual(len(first["integrity_record_sha256"]), 64)

    def test_tampered_state_digest_is_rejected(self):
        with self.assertRaisesRegex(CiscoRouterStateIntegrityError, "digest mismatch"):
            verify_router_state_integrity(replace(normalized_state(), state_digest_sha256="9" * 64))

    def test_stale_catalog_is_rejected(self):
        with self.assertRaisesRegex(CiscoRouterStateIntegrityError, "stale or different"):
            verify_router_state_integrity(replace(normalized_state(), catalog_digest_sha256="8" * 64))

    def test_self_completion_or_authority_claim_is_rejected(self):
        with self.assertRaisesRegex(CiscoRouterStateIntegrityError, "self-assert"):
            verify_router_state_integrity(replace(normalized_state(), c05_complete=True))
        with self.assertRaisesRegex(CiscoRouterStateIntegrityError, "safety boundary"):
            verify_router_state_integrity(replace(normalized_state(), production_write_authorized=True))


if __name__ == "__main__":
    unittest.main()
