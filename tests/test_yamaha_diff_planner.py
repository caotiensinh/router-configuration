import copy
import hashlib
import json
import unittest

from router_configuration.vendors.yamaha import (
    YamahaChangePlanError,
    YamahaStaticRouteIntent,
    build_change_plan,
    build_normalized_state,
    validate_change_plan,
)


class YamahaDiffPlannerTests(unittest.TestCase):
    def setUp(self) -> None:
        self.environment = "RTX3510 Rev.23.01.03\nCPU: 3%\n"
        self.route_output = """# show ip route
宛先ネットワーク    ゲートウェイ     インタフェース  種別  付加情報
default             203.0.113.1            LAN2  static
10.0.0.0/8          192.0.2.1              LAN1  static
192.168.0.0/24      192.168.0.1            LAN1  implicit
"""
        self.lan_outputs = {
            "show status lan1": "LAN1 observation payload\n",
            "show status lan2": "LAN2 observation payload\n",
            "show status lan3": "LAN3 observation payload\n",
            "show status lan4": "LAN4 observation payload\n",
        }

    def _state(self, route_output: str | None = None) -> dict:
        return build_normalized_state(
            environment_output=self.environment,
            route_output=route_output or self.route_output,
            lan_outputs=self.lan_outputs,
        )

    @staticmethod
    def _rehash(plan: dict) -> None:
        plan.pop("plan_sha256", None)
        canonical = json.dumps(plan, sort_keys=True, separators=(",", ":"))
        plan["plan_sha256"] = hashlib.sha256(canonical.encode()).hexdigest()

    def test_existing_exact_static_route_requires_no_change(self) -> None:
        plan = build_change_plan(
            current_state=self._state(),
            required_static_routes=(
                YamahaStaticRouteIntent("default", "203.0.113.1"),
            ),
        )
        self.assertEqual(plan["status"], "NO_CHANGE_REQUIRED")
        self.assertEqual(plan["route_actions"][0]["status"], "PRESENT")
        self.assertIsNone(plan["candidate_render_plan"])
        self.assertFalse(plan["requires_human_approval"])

    def test_same_gateway_non_static_route_does_not_satisfy_static_intent(self) -> None:
        plan = build_change_plan(
            current_state=self._state(),
            required_static_routes=(
                YamahaStaticRouteIntent("192.168.0.0/24", "192.168.0.1"),
            ),
        )
        self.assertEqual(plan["status"], "BLOCKED")
        self.assertEqual(
            plan["route_actions"][0]["blocker_code"],
            "NON_STATIC_CURRENT_ROUTE",
        )

    def test_missing_route_becomes_bounded_candidate_addition(self) -> None:
        plan = build_change_plan(
            current_state=self._state(),
            required_static_routes=(
                YamahaStaticRouteIntent("172.16.0.0/16", "192.0.2.254"),
            ),
        )
        self.assertEqual(plan["status"], "CANDIDATE_READY_FOR_REVIEW")
        self.assertTrue(plan["review_ready"])
        self.assertEqual(plan["route_actions"][0]["status"], "ADD")
        self.assertEqual(
            plan["candidate_render_plan"]["commands"],
            ["ip route 172.16.0.0/16 gateway 192.0.2.254"],
        )
        self.assertTrue(plan["requires_human_approval"])
        self.assertFalse(plan["apply_authorized"])
        self.assertFalse(plan["save_authorized"])

    def test_destination_with_different_gateway_is_blocked(self) -> None:
        plan = build_change_plan(
            current_state=self._state(),
            required_static_routes=(
                YamahaStaticRouteIntent("default", "198.51.100.1"),
            ),
        )
        self.assertEqual(plan["status"], "BLOCKED")
        self.assertEqual(
            plan["route_actions"][0]["blocker_code"],
            "ROUTE_DESTINATION_CONFLICT",
        )
        self.assertIsNone(plan["candidate_render_plan"])
        self.assertFalse(plan["review_ready"])

    def test_multiple_current_paths_for_required_destination_are_ambiguous(self) -> None:
        route_output = """default 203.0.113.1 LAN2 static
default 203.0.113.1 LAN3 static
192.168.0.0/24 192.168.0.1 LAN1 implicit
"""
        plan = build_change_plan(
            current_state=self._state(route_output),
            required_static_routes=(
                YamahaStaticRouteIntent("default", "203.0.113.1"),
            ),
        )
        self.assertEqual(plan["status"], "BLOCKED")
        self.assertEqual(
            plan["route_actions"][0]["blocker_code"],
            "AMBIGUOUS_CURRENT_ROUTE",
        )

    def test_interface_request_is_blocked_until_current_address_surface_exists(self) -> None:
        plan = build_change_plan(
            current_state=self._state(),
            interface_addresses={"lan1": "192.0.2.10/24"},
        )
        self.assertEqual(plan["status"], "BLOCKED")
        self.assertEqual(
            plan["interface_actions"][0]["blocker_code"],
            "CURRENT_INTERFACE_ADDRESS_UNAVAILABLE",
        )
        self.assertIsNone(plan["candidate_render_plan"])

    def test_independent_safe_addition_is_preserved_but_plan_stays_blocked(self) -> None:
        plan = build_change_plan(
            current_state=self._state(),
            required_static_routes=(
                YamahaStaticRouteIntent("172.16.0.0/16", "192.0.2.254"),
            ),
            interface_addresses={"lan1": "192.0.2.10/24"},
        )
        self.assertEqual(plan["status"], "BLOCKED")
        self.assertFalse(plan["review_ready"])
        self.assertEqual(
            plan["candidate_render_plan"]["commands"],
            ["ip route 172.16.0.0/16 gateway 192.0.2.254"],
        )
        self.assertFalse(plan["execution_ready"])

    def test_unmentioned_current_routes_are_never_deleted(self) -> None:
        plan = build_change_plan(
            current_state=self._state(),
            required_static_routes=(
                YamahaStaticRouteIntent("default", "203.0.113.1"),
            ),
        )
        self.assertEqual(
            plan["deletion_semantics"],
            "not_inferred_additive_requirement_scope",
        )
        self.assertEqual(plan["removal_commands"], [])

    def test_invalid_current_state_and_invalid_desired_route_fail_closed(self) -> None:
        state = self._state()
        state["ipv4_routes"][0]["gateway"] = "changed-without-rehash"
        with self.assertRaises(YamahaChangePlanError):
            build_change_plan(current_state=state)

        with self.assertRaises(YamahaChangePlanError):
            build_change_plan(
                current_state=self._state(),
                required_static_routes=(
                    YamahaStaticRouteIntent("10.0.0.1/24", "192.0.2.1"),
                ),
            )

    def test_plan_digest_and_write_boundary_detect_tampering(self) -> None:
        plan = build_change_plan(
            current_state=self._state(),
            required_static_routes=(
                YamahaStaticRouteIntent("172.16.0.0/16", "192.0.2.254"),
            ),
        )
        tampered = copy.deepcopy(plan)
        tampered["apply_authorized"] = True
        self._rehash(tampered)
        with self.assertRaises(YamahaChangePlanError):
            validate_change_plan(tampered)

        tampered = copy.deepcopy(plan)
        tampered["removal_commands"] = ["no ip route default"]
        self._rehash(tampered)
        with self.assertRaises(YamahaChangePlanError):
            validate_change_plan(tampered)

    def test_rehashed_action_inconsistency_is_rejected(self) -> None:
        plan = build_change_plan(
            current_state=self._state(),
            required_static_routes=(
                YamahaStaticRouteIntent("172.16.0.0/16", "192.0.2.254"),
            ),
        )
        tampered = copy.deepcopy(plan)
        tampered["route_actions"][0]["gateway"] = "192.0.2.253"
        self._rehash(tampered)
        with self.assertRaises(YamahaChangePlanError):
            validate_change_plan(tampered)

    def test_rehashed_blocker_inconsistency_is_rejected(self) -> None:
        plan = build_change_plan(
            current_state=self._state(),
            required_static_routes=(
                YamahaStaticRouteIntent("default", "198.51.100.1"),
            ),
        )
        tampered = copy.deepcopy(plan)
        tampered["blockers"][0]["code"] = "FAKE_BLOCKER"
        self._rehash(tampered)
        with self.assertRaises(YamahaChangePlanError):
            validate_change_plan(tampered)


if __name__ == "__main__":
    unittest.main()
