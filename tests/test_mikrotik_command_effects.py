import unittest

from router_configuration.vendors.mikrotik.command_effects import validate_effect_order
from router_configuration.vendors.mikrotik.script_planner import (
    MikroTikCommandPrimitive,
    MikroTikScriptContract,
)


def _cmd(cid, section, index):
    return MikroTikCommandPrimitive(cid, section, f"/{cid}", 30, cid.split('.')[0], index)


def _contract(commands):
    return MikroTikScriptContract(
        routeros_version="7.24.1",
        render_sha256="render-1",
        commands=tuple(commands),
        dependencies=(),
        knowledge_ids=("cli-reference",),
    )


class MikroTikCommandEffectsTests(unittest.TestCase):
    def test_requirement_without_transaction_producer_is_external_precondition(self):
        contract = _contract(
            (
                _cmd("firewall.00.stage-guard", "firewall_filter", 0),
                _cmd("routing.10.default", "ip_route", 1),
                _cmd("firewall.30.rule.010-established-related", "firewall_filter", 2),
                _cmd("firewall.99.remove-stage-guard", "firewall_filter", 3),
            )
        )
        findings = validate_effect_order(
            contract,
            (
                "firewall.00.stage-guard",
                "routing.10.default",
                "firewall.30.rule.010-established-related",
                "firewall.99.remove-stage-guard",
            ),
        )
        self.assertFalse(findings)

    def test_transaction_local_producer_must_precede_consumer(self):
        contract = _contract(
            (
                _cmd("wireguard.10.interface", "wireguard_interface", 0),
                _cmd("wireguard.20.address.001", "wireguard_address", 1),
                _cmd("wireguard.30.peer.001", "wireguard_peer", 2),
            )
        )
        findings = validate_effect_order(
            contract,
            (
                "wireguard.10.interface",
                "wireguard.30.peer.001",
                "wireguard.20.address.001",
            ),
        )
        self.assertIn("missing_requirement", {item.code for item in findings})
        self.assertIn("wireguard.30.peer.001", {item.command_id for item in findings})

    def test_independent_subsystem_does_not_satisfy_or_break_firewall_capabilities(self):
        contract = _contract(
            (
                _cmd("firewall.00.stage-guard", "firewall_filter", 0),
                _cmd("firewall.01.cleanup-chain", "firewall_filter", 1),
                _cmd("routing.10.default", "ip_route", 2),
                _cmd("firewall.30.rule.010-established-related", "firewall_filter", 3),
            )
        )
        findings = validate_effect_order(
            contract,
            (
                "firewall.00.stage-guard",
                "routing.10.default",
                "firewall.01.cleanup-chain",
                "firewall.30.rule.010-established-related",
            ),
        )
        self.assertFalse(findings)


if __name__ == "__main__":
    unittest.main()
