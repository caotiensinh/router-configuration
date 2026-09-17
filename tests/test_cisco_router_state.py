import unittest

from router_configuration.vendors.cisco.router_state import (
    CiscoRouterStateError,
    load_router_state_catalog,
    normalize_router_state,
    router_state_catalog_digest,
)


MODULES = {"Cisco-IOS-XE-interfaces-oper", "ietf-routing"}
SCHEMA_DIGEST = "a" * 64


class CiscoRouterNormalizedStateTests(unittest.TestCase):
    def _interfaces(self):
        return [
            {
                "name": "GigabitEthernet0/0/1",
                "vrf": "Global",
                "admin-status": "if-state-up",
                "oper-status": "if-oper-state-ready",
                "ipv4": "192.0.2.1",
                "ipv4-subnet-mask": "255.255.255.0",
                "ipv6-addrs": ["2001:db8::1", "fe80::1"],
                "ignored-operational-field": 123,
            },
            {
                "name": "Loopback0",
                "admin-status": "if-state-up",
                "oper-status": "if-oper-state-ready",
                "ipv4": "198.51.100.1",
                "ipv4-subnet-mask": "255.255.255.255",
                "ipv6-addrs": [],
            },
        ]

    def _routes(self):
        return [
            {
                "destination-prefix": "0.0.0.0/0",
                "source-protocol": "rt:static",
                "route-preference": 1,
                "metric": 0,
                "next-hop": {"next-hop-address": "192.0.2.254"},
                "active": None,
            },
            {
                "destination-prefix": "198.51.100.1/32",
                "source-protocol": "rt:direct",
                "next-hop": {"outgoing-interface": "Loopback0"},
            },
        ]

    def test_catalog_is_pinned_read_only_and_live_gated(self) -> None:
        catalog = load_router_state_catalog()
        self.assertEqual(catalog["role"], "router")
        self.assertFalse(catalog["write_authorized"])
        self.assertFalse(catalog["physical_device_verified"])
        self.assertFalse(catalog["synthetic_fixture_can_complete_c05"])
        self.assertTrue(catalog["live_state_evidence_required_for_c05"])
        self.assertEqual(set(catalog["documentation_trains"]), {"17.18", "26"})
        self.assertEqual(len(router_state_catalog_digest()), 64)

    def test_router_state_normalizes_deterministically(self) -> None:
        first = normalize_router_state(
            model="C8300-2N2S-6T",
            iosxe_version="17.18.1a",
            schema_inventory_digest_sha256=SCHEMA_DIGEST,
            observed_modules=MODULES,
            interface_records=self._interfaces(),
            route_records=self._routes(),
        )
        second = normalize_router_state(
            model="C8300-2N2S-6T",
            iosxe_version="17.18.1a",
            schema_inventory_digest_sha256=SCHEMA_DIGEST,
            observed_modules=reversed(sorted(MODULES)),
            interface_records=list(reversed(self._interfaces())),
            route_records=list(reversed(self._routes())),
        )
        self.assertEqual(first.state_digest_sha256, second.state_digest_sha256)
        self.assertEqual(first.platform_family, "Catalyst 8300")
        self.assertEqual(first.documentation_train, "17.18")
        self.assertEqual(first.interfaces[0].name, "GigabitEthernet0/0/1")
        self.assertEqual(first.interfaces[0].ipv4_cidr, "192.0.2.1/24")
        self.assertEqual(first.interfaces[0].ipv6_addresses, ("2001:db8::1", "fe80::1"))
        self.assertEqual(first.routes[0].destination_prefix, "0.0.0.0/0")
        self.assertFalse(first.c05_complete)
        self.assertFalse(first.production_write_authorized)
        self.assertFalse(first.physical_device_verified)

    def test_iosxe_26_router_is_source_bound(self) -> None:
        state = normalize_router_state(
            model="C8500-12X",
            iosxe_version="26.1.1",
            schema_inventory_digest_sha256=SCHEMA_DIGEST,
            observed_modules=MODULES,
            interface_records=self._interfaces(),
            route_records=self._routes(),
        )
        self.assertEqual(state.documentation_train, "26")
        self.assertEqual(state.platform_family, "Catalyst 8500")

    def test_switch_model_is_rejected_from_router_lane(self) -> None:
        with self.assertRaises(CiscoRouterStateError):
            normalize_router_state(
                model="C9300-24T",
                iosxe_version="17.18.1a",
                schema_inventory_digest_sha256=SCHEMA_DIGEST,
                observed_modules=MODULES,
                interface_records=self._interfaces(),
                route_records=self._routes(),
            )

    def test_missing_live_module_inventory_fails_closed(self) -> None:
        with self.assertRaisesRegex(CiscoRouterStateError, "required YANG modules"):
            normalize_router_state(
                model="C8300-2N2S-6T",
                iosxe_version="17.18.1a",
                schema_inventory_digest_sha256=SCHEMA_DIGEST,
                observed_modules={"Cisco-IOS-XE-interfaces-oper"},
                interface_records=self._interfaces(),
                route_records=self._routes(),
            )
        with self.assertRaisesRegex(CiscoRouterStateError, "inventory digest"):
            normalize_router_state(
                model="C8300-2N2S-6T",
                iosxe_version="17.18.1a",
                schema_inventory_digest_sha256="bad",
                observed_modules=MODULES,
                interface_records=self._interfaces(),
                route_records=self._routes(),
            )

    def test_invalid_interface_address_or_state_fails_closed(self) -> None:
        broken = self._interfaces()
        broken[0]["ipv4-subnet-mask"] = "255.0.255.0"
        with self.assertRaises(CiscoRouterStateError):
            normalize_router_state(
                model="C8300-2N2S-6T", iosxe_version="17.18.1a",
                schema_inventory_digest_sha256=SCHEMA_DIGEST, observed_modules=MODULES,
                interface_records=broken, route_records=self._routes(),
            )
        broken = self._interfaces()
        broken[0]["oper-status"] = "up-ish"
        with self.assertRaises(CiscoRouterStateError):
            normalize_router_state(
                model="C8300-2N2S-6T", iosxe_version="17.18.1a",
                schema_inventory_digest_sha256=SCHEMA_DIGEST, observed_modules=MODULES,
                interface_records=broken, route_records=self._routes(),
            )

    def test_duplicate_interface_or_route_key_fails_closed(self) -> None:
        duplicate_interfaces = self._interfaces() + [dict(self._interfaces()[0])]
        with self.assertRaisesRegex(CiscoRouterStateError, "duplicate interface"):
            normalize_router_state(
                model="C8300-2N2S-6T", iosxe_version="17.18.1a",
                schema_inventory_digest_sha256=SCHEMA_DIGEST, observed_modules=MODULES,
                interface_records=duplicate_interfaces, route_records=self._routes(),
            )
        duplicate_routes = self._routes() + [
            {
                "destination-prefix": "0.0.0.0/0",
                "source-protocol": "rt:direct",
                "next-hop": {"outgoing-interface": "GigabitEthernet0/0/1"},
            }
        ]
        with self.assertRaisesRegex(CiscoRouterStateError, "duplicate destination-prefix"):
            normalize_router_state(
                model="C8300-2N2S-6T", iosxe_version="17.18.1a",
                schema_inventory_digest_sha256=SCHEMA_DIGEST, observed_modules=MODULES,
                interface_records=self._interfaces(), route_records=duplicate_routes,
            )

    def test_ipv6_route_in_bounded_ipv4_rib_is_rejected(self) -> None:
        routes = [{
            "destination-prefix": "2001:db8::/32",
            "source-protocol": "rt:static",
            "next-hop": {"next-hop-address": "2001:db8::1"},
        }]
        with self.assertRaisesRegex(CiscoRouterStateError, "IPv4 prefixes only"):
            normalize_router_state(
                model="C8300-2N2S-6T", iosxe_version="17.18.1a",
                schema_inventory_digest_sha256=SCHEMA_DIGEST, observed_modules=MODULES,
                interface_records=self._interfaces(), route_records=routes,
            )

    def test_next_hop_choice_is_validated(self) -> None:
        routes = [{
            "destination-prefix": "203.0.113.0/24",
            "source-protocol": "rt:static",
            "next-hop": {"special-next-hop": "blackhole", "outgoing-interface": "Gi0/0/1"},
        }]
        with self.assertRaisesRegex(CiscoRouterStateError, "special next-hop"):
            normalize_router_state(
                model="C8300-2N2S-6T", iosxe_version="17.18.1a",
                schema_inventory_digest_sha256=SCHEMA_DIGEST, observed_modules=MODULES,
                interface_records=self._interfaces(), route_records=routes,
            )

    def test_sensitive_fields_are_rejected_before_normalization(self) -> None:
        interfaces = self._interfaces()
        interfaces[0]["password"] = "should-never-enter-normalized-state"
        with self.assertRaisesRegex(CiscoRouterStateError, "sensitive field"):
            normalize_router_state(
                model="C8300-2N2S-6T", iosxe_version="17.18.1a",
                schema_inventory_digest_sha256=SCHEMA_DIGEST, observed_modules=MODULES,
                interface_records=interfaces, route_records=self._routes(),
            )


if __name__ == "__main__":
    unittest.main()
