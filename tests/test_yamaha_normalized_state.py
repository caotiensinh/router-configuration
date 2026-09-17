import copy
import unittest

from router_configuration.vendors.yamaha import (
    YamahaNormalizedStateError,
    build_normalized_state,
    parse_ipv4_routes,
    validate_normalized_state,
)


class YamahaNormalizedStateTests(unittest.TestCase):
    def setUp(self) -> None:
        self.environment = "RTX3510 Rev.23.01.03\nCPU: 3%\n"
        self.route_output = """# show ip route
宛先ネットワーク    ゲートウェイ     インタフェース  種別  付加情報
default             203.0.113.1            LAN2  static
192.168.0.0/24      192.168.0.1            LAN1  implicit
192.168.1.0/24      -                 TUNNEL[1]  temporary
"""
        self.lan_outputs = {
            "show status lan1": "LAN1 observation payload\n",
            "show status lan2": "LAN2 observation payload\n",
            "show status lan3": "LAN3 observation payload\n",
            "show status lan4": "LAN4 observation payload\n",
        }

    def test_documented_route_table_shape_is_normalized(self) -> None:
        routes = parse_ipv4_routes(self.route_output)
        self.assertEqual(len(routes), 3)
        by_destination = {route.destination: route for route in routes}

        default = by_destination["default"]
        self.assertEqual(default.gateway, "203.0.113.1")
        self.assertEqual(default.interface, "LAN2")
        self.assertEqual(default.route_type, "static")
        self.assertTrue(default.active)

        tunnel = by_destination["192.168.1.0/24"]
        self.assertIsNone(tunnel.gateway)
        self.assertEqual(tunnel.interface, "TUNNEL[1]")
        self.assertEqual(tunnel.route_type, "temporary")

    def test_route_output_is_deterministic_independent_of_input_order(self) -> None:
        first = parse_ipv4_routes(self.route_output)
        reordered = """192.168.1.0/24 - TUNNEL[1] temporary
default 203.0.113.1 LAN2 static
192.168.0.0/24 192.168.0.1 LAN1 implicit
"""
        second = parse_ipv4_routes(reordered)
        self.assertEqual(first, second)

    def test_route_parser_rejects_malformed_or_non_ipv4_rows(self) -> None:
        for output in (
            "not-enough-fields\n",
            "2001:db8::/64 - LAN1 static\n",
            "bad-prefix 192.0.2.1 LAN1 static\n",
        ):
            with self.subTest(output=output):
                with self.assertRaises(YamahaNormalizedStateError):
                    parse_ipv4_routes(output)

    def test_partial_state_marks_lan_link_semantics_unknown(self) -> None:
        state = build_normalized_state(
            environment_output=self.environment,
            route_output=self.route_output,
            lan_outputs=self.lan_outputs,
        )
        validate_normalized_state(state)

        self.assertEqual(state["device"]["model"], "RTX3510")
        self.assertEqual(state["device"]["firmware"], "23.01.03")
        self.assertEqual(
            [item["name"] for item in state["interfaces"]],
            ["lan1", "lan2", "lan3", "lan4"],
        )
        for interface in state["interfaces"]:
            self.assertEqual(interface["operational_state"], "unknown")
            self.assertFalse(interface["parsed_link_state"])
            self.assertEqual(len(interface["observation_sha256"]), 64)

    def test_partial_state_does_not_embed_raw_outputs_or_promote_live_status(self) -> None:
        state = build_normalized_state(
            environment_output=self.environment,
            route_output=self.route_output,
            lan_outputs=self.lan_outputs,
        )
        source = state["source"]
        self.assertFalse(source["raw_outputs_embedded"])
        self.assertFalse(source["transport_verified"])
        self.assertFalse(source["least_privilege_verified"])
        self.assertFalse(source["live_device_verified"])
        self.assertFalse(source["physical_device_verified"])
        self.assertFalse(source["production_write_authorized"])
        self.assertIn("interface_link_state_parser", source["missing_surfaces"])

    def test_missing_lan_observation_fails_closed(self) -> None:
        outputs = dict(self.lan_outputs)
        outputs.pop("show status lan4")
        with self.assertRaises(YamahaNormalizedStateError):
            build_normalized_state(
                environment_output=self.environment,
                route_output=self.route_output,
                lan_outputs=outputs,
            )

    def test_non_admitted_firmware_fails_closed(self) -> None:
        with self.assertRaises(YamahaNormalizedStateError):
            build_normalized_state(
                environment_output="RTX3510 Rev.23.01.02\n",
                route_output=self.route_output,
                lan_outputs=self.lan_outputs,
            )

    def test_state_tampering_is_rejected(self) -> None:
        state = build_normalized_state(
            environment_output=self.environment,
            route_output=self.route_output,
            lan_outputs=self.lan_outputs,
        )
        tampered = copy.deepcopy(state)
        tampered["ipv4_routes"][0]["route_type"] = "changed"
        with self.assertRaises(YamahaNormalizedStateError):
            validate_normalized_state(tampered)

    def test_unknown_lan_state_cannot_be_self_promoted(self) -> None:
        state = build_normalized_state(
            environment_output=self.environment,
            route_output=self.route_output,
            lan_outputs=self.lan_outputs,
        )
        promoted = copy.deepcopy(state)
        promoted["interfaces"][0]["operational_state"] = "up"
        promoted["interfaces"][0]["parsed_link_state"] = True
        with self.assertRaises(YamahaNormalizedStateError):
            validate_normalized_state(promoted)

    def test_live_or_write_claims_are_rejected(self) -> None:
        state = build_normalized_state(
            environment_output=self.environment,
            route_output=self.route_output,
            lan_outputs=self.lan_outputs,
        )
        for field in (
            "transport_verified",
            "least_privilege_verified",
            "live_device_verified",
            "physical_device_verified",
            "production_write_authorized",
        ):
            with self.subTest(field=field):
                promoted = copy.deepcopy(state)
                promoted["source"][field] = True
                with self.assertRaises(YamahaNormalizedStateError):
                    validate_normalized_state(promoted)


if __name__ == "__main__":
    unittest.main()
