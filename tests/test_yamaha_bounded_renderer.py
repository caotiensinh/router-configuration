import copy
import hashlib
import json
import unittest

from router_configuration.vendors.yamaha.renderer import (
    YamahaRenderError,
    YamahaStaticRouteIntent,
    render_candidate_plan,
    validate_candidate_plan,
)


class YamahaBoundedRendererTests(unittest.TestCase):
    def test_exact_source_bound_commands_are_rendered(self) -> None:
        plan = render_candidate_plan(
            interface_addresses={
                "lan1": "192.168.100.1/24",
                "LAN4": "10.0.0.1/30",
            },
            static_routes=(
                YamahaStaticRouteIntent("default", "203.0.113.1"),
                YamahaStaticRouteIntent("10.20.0.0/16", "10.0.0.2"),
            ),
        )
        self.assertEqual(
            plan["commands"],
            [
                "ip lan1 address 192.168.100.1/24",
                "ip lan4 address 10.0.0.1/30",
                "ip route 10.20.0.0/16 gateway 10.0.0.2",
                "ip route default gateway 203.0.113.1",
            ],
        )
        self.assertEqual(
            plan["documentation_source_ids"],
            ["YAMAHA-RTX-CMDREF", "YAMAHA-RTX3510-USERGUIDE"],
        )

    def test_plan_is_deterministic(self) -> None:
        first = render_candidate_plan(
            interface_addresses={"lan2": "192.0.2.1/24", "lan1": "198.51.100.1/24"},
            static_routes=(
                YamahaStaticRouteIntent("10.2.0.0/16", "192.0.2.2"),
                YamahaStaticRouteIntent("10.1.0.0/16", "198.51.100.2"),
            ),
        )
        second = render_candidate_plan(
            interface_addresses={"lan1": "198.51.100.1/24", "lan2": "192.0.2.1/24"},
            static_routes=(
                YamahaStaticRouteIntent("10.1.0.0/16", "198.51.100.2"),
                YamahaStaticRouteIntent("10.2.0.0/16", "192.0.2.2"),
            ),
        )
        self.assertEqual(first, second)

    def test_write_transport_and_save_remain_disabled(self) -> None:
        plan = render_candidate_plan(interface_addresses={"lan1": "192.0.2.1/24"})
        self.assertEqual(plan["mode"], "candidate_dry_run_only")
        self.assertFalse(plan["transport_authorized"])
        self.assertFalse(plan["apply_authorized"])
        self.assertFalse(plan["save_authorized"])
        self.assertFalse(plan["production_write_authorized"])
        self.assertFalse(plan["physical_device_verified"])
        self.assertTrue(plan["requires_current_state"])
        self.assertTrue(plan["requires_prechange_backup"])
        self.assertTrue(plan["requires_human_approval"])
        self.assertTrue(plan["requires_postchange_verification"])

    def test_unknown_interface_and_injection_fail_closed(self) -> None:
        for interface, address in (
            ("lan5", "192.0.2.1/24"),
            ("lan1; save", "192.0.2.1/24"),
            ("lan1", "192.0.2.1/24\nsave"),
        ):
            with self.subTest(interface=interface, address=address):
                with self.assertRaises(YamahaRenderError):
                    render_candidate_plan(interface_addresses={interface: address})

    def test_ipv6_or_missing_prefix_interface_address_is_rejected(self) -> None:
        for address in ("2001:db8::1/64", "192.0.2.1"):
            with self.subTest(address=address):
                with self.assertRaises(YamahaRenderError):
                    render_candidate_plan(interface_addresses={"lan1": address})

    def test_static_route_requires_network_destination_and_ipv4_gateway(self) -> None:
        bad = (
            YamahaStaticRouteIntent("10.0.0.1/24", "192.0.2.1"),
            YamahaStaticRouteIntent("2001:db8::/64", "192.0.2.1"),
            YamahaStaticRouteIntent("10.0.0.0/24", "2001:db8::1"),
            YamahaStaticRouteIntent("10.0.0.0/24", "pp 1"),
        )
        for intent in bad:
            with self.subTest(intent=intent):
                with self.assertRaises(YamahaRenderError):
                    render_candidate_plan(static_routes=(intent,))

    def test_one_gateway_per_destination_is_enforced_in_y04(self) -> None:
        with self.assertRaises(YamahaRenderError):
            render_candidate_plan(
                static_routes=(
                    YamahaStaticRouteIntent("default", "192.0.2.1"),
                    YamahaStaticRouteIntent("default", "198.51.100.1"),
                )
            )

    def test_empty_plan_is_rejected(self) -> None:
        with self.assertRaises(YamahaRenderError):
            render_candidate_plan()

    def test_plan_digest_detects_tampering(self) -> None:
        plan = render_candidate_plan(interface_addresses={"lan1": "192.0.2.1/24"})
        tampered = copy.deepcopy(plan)
        tampered["commands"][0] = "ip lan1 address 192.0.2.2/24"
        with self.assertRaises(YamahaRenderError):
            validate_candidate_plan(tampered)

    def test_rehashed_unapproved_command_is_still_rejected(self) -> None:
        plan = render_candidate_plan(interface_addresses={"lan1": "192.0.2.1/24"})
        tampered = copy.deepcopy(plan)
        tampered["commands"] = ["save"]
        tampered.pop("plan_sha256")
        canonical = json.dumps(tampered, sort_keys=True, separators=(",", ":"))
        tampered["plan_sha256"] = hashlib.sha256(canonical.encode()).hexdigest()
        with self.assertRaises(YamahaRenderError):
            validate_candidate_plan(tampered)

    def test_rehashed_invalid_ipv4_command_is_rejected(self) -> None:
        plan = render_candidate_plan(interface_addresses={"lan1": "192.0.2.1/24"})
        tampered = copy.deepcopy(plan)
        tampered["commands"] = ["ip lan1 address 999.999.999.999/24"]
        tampered.pop("plan_sha256")
        canonical = json.dumps(tampered, sort_keys=True, separators=(",", ":"))
        tampered["plan_sha256"] = hashlib.sha256(canonical.encode()).hexdigest()
        with self.assertRaises(YamahaRenderError):
            validate_candidate_plan(tampered)


if __name__ == "__main__":
    unittest.main()
