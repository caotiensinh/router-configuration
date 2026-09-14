import json
import unittest

from router_configuration.vendors.mikrotik.inference import MikroTikReasoningResult
from router_configuration.vendors.mikrotik.script_planner import (
    MikroTikOrderingProposal,
    MikroTikScriptPlanError,
    build_script_contract,
    compile_script,
    deterministic_order,
    parse_ai_ordering,
    propose_order_with_ai,
    validate_ordering,
)


def _render_plan():
    return {
        "complete": True,
        "blocked_operations": [],
        "transport_present": False,
        "write_authorized": False,
        "render_sha256": "render-sha-001",
        "commands": [
            {
                "command_id": "firewall.00.stage-guard",
                "section": "firewall_filter",
                "command": "/ip/firewall/filter/add chain=input action=drop comment=stage",
                "risk": 30,
            },
            {
                "command_id": "firewall.30.rule.010-established-related",
                "section": "firewall_filter",
                "command": "/ip/firewall/filter/add chain=input action=accept connection-state=established,related",
                "risk": 30,
            },
            {
                "command_id": "routing.10.default",
                "section": "routing",
                "command": "/ip/route/add dst-address=0.0.0.0/0 gateway=192.0.2.1",
                "risk": 30,
            },
            {
                "command_id": "firewall.99.remove-stage-guard",
                "section": "firewall_filter",
                "command": "/ip/firewall/filter/remove [find where comment=stage]",
                "risk": 30,
            },
        ],
    }


class _FakeProvider:
    def reason(self, request):
        payload = {
            "ordered_command_ids": [
                "firewall.00.stage-guard",
                "routing.10.default",
                "firewall.30.rule.010-established-related",
                "firewall.99.remove-stage-guard",
            ],
            "rationale": "preserve firewall guard dependencies while routing is independent",
            "knowledge_ids": ["cli-reference", "scripting-import-validation"],
        }
        return MikroTikReasoningResult("fake", "fake", json.dumps(payload), ())


class MikroTikScriptPlannerTests(unittest.TestCase):
    def test_model_contract_never_contains_raw_cli(self):
        contract = build_script_contract(render_plan=_render_plan(), routeros_version="7.24.1")
        payload = contract.model_payload()
        self.assertFalse(payload["raw_routeros_cli_present"])
        self.assertTrue(payload["commands"])
        self.assertTrue(all("command" not in item for item in payload["commands"]))
        self.assertNotIn("/ip/", json.dumps(payload))

    def test_ai_cannot_return_raw_command_fields(self):
        contract = build_script_contract(render_plan=_render_plan(), routeros_version="7.24.1")
        response = json.dumps(
            {
                "ordered_command_ids": [item.command_id for item in contract.commands],
                "rationale": "x",
                "knowledge_ids": ["cli-reference"],
                "command": "/system/reset-configuration",
            }
        )
        with self.assertRaises(MikroTikScriptPlanError):
            parse_ai_ordering(response, contract)

    def test_dependency_violation_is_rejected(self):
        contract = build_script_contract(render_plan=_render_plan(), routeros_version="7.24.1")
        proposal = MikroTikOrderingProposal(
            (
                "firewall.30.rule.010-established-related",
                "firewall.00.stage-guard",
                "routing.10.default",
                "firewall.99.remove-stage-guard",
            ),
            "bad",
            ("cli-reference",),
            "test",
        )
        with self.assertRaises(MikroTikScriptPlanError):
            validate_ordering(contract, proposal)

    def test_ai_orders_ids_but_renderer_commands_remain_immutable(self):
        contract = build_script_contract(render_plan=_render_plan(), routeros_version="7.24.1")
        proposal = propose_order_with_ai(provider=_FakeProvider(), contract=contract)
        artifact = compile_script(contract=contract, proposal=proposal, file_name="change-001")
        self.assertTrue(artifact.file_name.endswith(".rsc"))
        self.assertEqual(len(artifact.script_sha256), 64)
        self.assertTrue(artifact.dry_run_required)
        self.assertFalse(artifact.write_authorized)
        self.assertIn("verbose=yes dry-run", artifact.dry_run_command)
        self.assertIn("/ip/route/add", artifact.script)
        self.assertLess(
            artifact.script.index("firewall.00.stage-guard"),
            artifact.script.index("firewall.99.remove-stage-guard"),
        )

    def test_deterministic_fallback_needs_no_ai(self):
        contract = build_script_contract(render_plan=_render_plan(), routeros_version="7.24.1")
        proposal = deterministic_order(contract)
        validate_ordering(contract, proposal)
        self.assertEqual(set(proposal.ordered_command_ids), {item.command_id for item in contract.commands})

    def test_incomplete_render_plan_cannot_be_scripted(self):
        plan = _render_plan()
        plan["complete"] = False
        plan["blocked_operations"] = [{"operation_id": "vpn.wireguard"}]
        with self.assertRaises(MikroTikScriptPlanError):
            build_script_contract(render_plan=plan, routeros_version="7.24.1")


if __name__ == "__main__":
    unittest.main()
