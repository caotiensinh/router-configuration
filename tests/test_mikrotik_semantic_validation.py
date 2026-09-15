import unittest

from router_configuration.vendors.mikrotik.script_planner import (
    MikroTikCommandPrimitive,
    MikroTikDependency,
    MikroTikOrderingProposal,
    MikroTikScriptArtifact,
    MikroTikScriptContract,
)
from router_configuration.vendors.mikrotik.semantic_validation import attest_semantics


def _script(ids):
    return MikroTikScriptArtifact(
        file_name="change.rsc",
        script="# test\n",
        script_sha256="a" * 64,
        render_sha256="render-1",
        ordered_command_ids=tuple(ids),
        dry_run_command='/import file-name="change.rsc" verbose=yes dry-run',
    )


def _contract(commands, dependencies=()):
    return MikroTikScriptContract(
        routeros_version="7.24.1",
        render_sha256="render-1",
        commands=tuple(commands),
        dependencies=tuple(dependencies),
        knowledge_ids=("cli-reference", "scripting-import-validation"),
    )


def _cmd(cid, section, index):
    return MikroTikCommandPrimitive(cid, section, f"/{cid}", 30, cid.split('.')[0], index)


class MikroTikSemanticValidationTests(unittest.TestCase):
    def test_same_routeros_section_cannot_be_reordered(self):
        commands = (
            _cmd("routing.10.first", "ip_route", 0),
            _cmd("pbr.10.independent", "routing_rule", 1),
            _cmd("routing.20.second", "ip_route", 2),
        )
        contract = _contract(commands)
        proposal = MikroTikOrderingProposal(
            ("routing.20.second", "pbr.10.independent", "routing.10.first"),
            "unsafe",
            contract.knowledge_ids,
            "ai",
        )
        attestation = attest_semantics(
            contract=contract,
            proposal=proposal,
            script=_script(proposal.ordered_command_ids),
        )
        self.assertFalse(attestation.passed)
        self.assertIn("section_order_changed", {item.code for item in attestation.findings})

    def test_wireguard_interface_address_peer_route_sequence_is_enforced(self):
        commands = (
            _cmd("wireguard.10.interface", "wireguard_interface", 0),
            _cmd("wireguard.20.address.001", "wireguard_address", 1),
            _cmd("wireguard.30.peer.001", "wireguard_peer", 2),
            _cmd("wireguard.40.route.001.001", "wireguard_route", 3),
        )
        contract = _contract(commands)
        proposal = MikroTikOrderingProposal(
            (
                "wireguard.10.interface",
                "wireguard.30.peer.001",
                "wireguard.20.address.001",
                "wireguard.40.route.001.001",
            ),
            "bad",
            contract.knowledge_ids,
            "ai",
        )
        attestation = attest_semantics(
            contract=contract,
            proposal=proposal,
            script=_script(proposal.ordered_command_ids),
        )
        self.assertFalse(attestation.passed)
        self.assertIn("wireguard_address_dependency", {item.code for item in attestation.findings})

    def test_valid_cross_subsystem_interleave_can_pass(self):
        commands = (
            _cmd("firewall.00.stage-guard", "firewall_filter", 0),
            _cmd("routing.10.default", "ip_route", 1),
            _cmd("firewall.30.rule.010-established-related", "firewall_filter", 2),
            _cmd("firewall.99.remove-stage-guard", "firewall_filter", 3),
        )
        dependencies = (
            MikroTikDependency("firewall.00.stage-guard", "firewall.30.rule.010-established-related", "guard"),
            MikroTikDependency("firewall.30.rule.010-established-related", "firewall.99.remove-stage-guard", "release"),
        )
        contract = _contract(commands, dependencies)
        ids = (
            "firewall.00.stage-guard",
            "routing.10.default",
            "firewall.30.rule.010-established-related",
            "firewall.99.remove-stage-guard",
        )
        proposal = MikroTikOrderingProposal(ids, "safe", contract.knowledge_ids, "ai")
        attestation = attest_semantics(contract=contract, proposal=proposal, script=_script(ids))
        self.assertTrue(attestation.passed)
        self.assertFalse(attestation.findings)

    def test_script_order_mismatch_fails_attestation(self):
        commands = (
            _cmd("routing.10.first", "ip_route", 0),
            _cmd("routing.20.second", "ip_route", 1),
        )
        contract = _contract(commands)
        proposal = MikroTikOrderingProposal(
            ("routing.10.first", "routing.20.second"),
            "safe",
            contract.knowledge_ids,
            "deterministic",
        )
        attestation = attest_semantics(
            contract=contract,
            proposal=proposal,
            script=_script(("routing.20.second", "routing.10.first")),
        )
        self.assertFalse(attestation.passed)
        self.assertIn("script_order_mismatch", {item.code for item in attestation.findings})


if __name__ == "__main__":
    unittest.main()
