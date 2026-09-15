import unittest
from unittest.mock import patch

from router_configuration.routeros_generation import RouterOSGenerationResult
from router_configuration.routeros_generation_v1 import generate_routeros_plan_v1
from router_configuration.routeros_vlan_renderer import RouterOSVlanRenderError


class RouterOSGenerationV1Tests(unittest.TestCase):
    def test_base_failure_is_returned_unchanged(self):
        base = RouterOSGenerationResult(
            errors=("readiness failed",),
            warnings=("w",),
            readiness={"ok": False},
        )
        with patch(
            "router_configuration.routeros_generation_v1.generate_routeros_plan",
            return_value=base,
        ) as generate, patch(
            "router_configuration.routeros_generation_v1.apply_state_bound_vlan_pbr_extensions"
        ) as extend:
            result = generate_routeros_plan_v1(profile={}, ir={}, evidence={})
        self.assertIs(result, base)
        generate.assert_called_once()
        extend.assert_not_called()

    def test_successful_base_is_extended_without_enabling_write(self):
        base = RouterOSGenerationResult(
            errors=(),
            warnings=(),
            readiness={"ok": True},
            render_plan={
                "commands": [],
                "blocked_operations": [],
                "transport_present": False,
                "apply_available": False,
                "write_authorized": False,
            },
        )
        extended = {
            **base.render_plan,
            "state_bound_extensions": {"vlan_segmentation": {"command_count": 3}},
        }
        with patch(
            "router_configuration.routeros_generation_v1.generate_routeros_plan",
            return_value=base,
        ), patch(
            "router_configuration.routeros_generation_v1.apply_state_bound_vlan_pbr_extensions",
            return_value=extended,
        ) as extend:
            result = generate_routeros_plan_v1(profile={"x": 1}, ir={"y": 2}, evidence={"z": 3})
        self.assertTrue(result.ok)
        self.assertEqual(result.render_plan, extended)
        self.assertFalse(result.render_plan["transport_present"])
        self.assertFalse(result.render_plan["apply_available"])
        self.assertFalse(result.render_plan["write_authorized"])
        extend.assert_called_once()

    def test_vlan_prerequisite_error_becomes_bounded_generation_error(self):
        base = RouterOSGenerationResult(
            errors=(),
            warnings=("existing warning",),
            readiness={"ok": True, "ir_sha256": "abc"},
            render_plan={
                "commands": [],
                "blocked_operations": [],
                "transport_present": False,
                "apply_available": False,
                "write_authorized": False,
            },
        )
        with patch(
            "router_configuration.routeros_generation_v1.generate_routeros_plan",
            return_value=base,
        ), patch(
            "router_configuration.routeros_generation_v1.apply_state_bound_vlan_pbr_extensions",
            side_effect=RouterOSVlanRenderError("verified management_path evidence is required"),
        ):
            result = generate_routeros_plan_v1(profile={}, ir={}, evidence={})
        self.assertFalse(result.ok)
        self.assertEqual(
            result.errors,
            ("vlan renderer: verified management_path evidence is required",),
        )
        self.assertEqual(result.warnings, ("existing warning",))
        self.assertEqual(result.readiness["ir_sha256"], "abc")
        self.assertIsNone(result.render_plan)


if __name__ == "__main__":
    unittest.main()
