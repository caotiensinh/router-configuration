import copy
import unittest

from router_configuration.routeros_pcc_renderer import (
    RouterOSPccRenderError,
    render_routeros_pcc,
)
from router_configuration.safe_subset_ir import IntentOperation, IntentRisk, SafeSubsetIR


def pcc_ir():
    return SafeSubsetIR(
        device_id="chr-pcc-test",
        operations=(
            IntentOperation(
                operation_id="routing.multiwan.capacity_weighted",
                feature="multiwan",
                resource="path_distribution_policy",
                attributes={
                    "mode": "capacity_weighted",
                    "weights": {"wan10g": 10, "wan1g": 1},
                    "failover": True,
                    "failback": "health_hysteresis",
                    "paths": {
                        "wan10g": {
                            "interface": "ether1",
                            "addressing": "static",
                            "address": "192.0.2.2/30",
                            "gateway": "192.0.2.1",
                            "table": "to-wan10g",
                            "failover_distance": 1,
                            "health_probe_targets": ["1.1.1.1", "8.8.8.8"],
                        },
                        "wan1g": {
                            "interface": "ether2",
                            "addressing": "static",
                            "address": "198.51.100.2/30",
                            "gateway": "198.51.100.1",
                            "table": "to-wan1g",
                            "failover_distance": 2,
                            "health_probe_targets": ["9.9.9.9", "208.67.222.222"],
                        },
                    },
                },
                risk=IntentRisk.HIGH,
                requires=("interfaces", "routing"),
            ),
        ),
    ).as_dict()


def clean_state():
    return {"firewall": {"filter": [], "nat": []}}


class RouterOSPccRendererTests(unittest.TestCase):
    def test_10_to_1_renderer_is_generation_only_and_complete(self):
        plan = render_routeros_pcc(ir=pcc_ir(), state=clean_state())
        payload = plan.as_dict()
        self.assertEqual(payload["schema_version"], "routeros-pcc-command-plan/1")
        self.assertEqual(payload["scope"], "generation_only")
        self.assertEqual(payload["command_count"], 21)
        self.assertFalse(payload["transport_present"])
        self.assertFalse(payload["apply_available"])
        self.assertFalse(payload["write_authorized"])

        sections = [command.section for command in plan.commands]
        self.assertEqual(sections.count("pcc_policy_route"), 8)
        self.assertEqual(sections.count("firewall_mangle"), 13)
        self.assertEqual(sections[:8], ["pcc_policy_route"] * 8)
        self.assertTrue(
            all(
                command.command_id.startswith("pcc.mangle.connection.")
                for command in plan.commands[8:19]
            )
        )
        self.assertTrue(
            all(
                command.command_id.startswith("pcc.mangle.routing.")
                for command in plan.commands[19:]
            )
        )

        connection_rules = [
            command.command
            for command in plan.commands
            if command.command_id.startswith("pcc.mangle.connection.")
        ]
        self.assertEqual(len(connection_rules), 11)
        for remainder in range(11):
            self.assertTrue(
                any(
                    f'per-connection-classifier="both-addresses-and-ports:11/{remainder}"'
                    in command
                    for command in connection_rules
                )
            )
        self.assertTrue(
            all("connection-state=new" in command for command in connection_rules)
        )
        self.assertTrue(
            all("connection-mark=no-mark" in command for command in connection_rules)
        )
        self.assertTrue(
            all("dst-address-type=!local" in command for command in connection_rules)
        )

        route_commands = [
            command.command
            for command in plan.commands
            if command.section == "pcc_policy_route"
        ]
        self.assertTrue(any('gateway="1.1.1.1@main"' in command for command in route_commands))
        self.assertTrue(any('routing-table="to-wan10g"' in command for command in route_commands))
        self.assertTrue(any('routing-table="to-wan1g"' in command for command in route_commands))

    def test_render_is_deterministic(self):
        first = render_routeros_pcc(ir=pcc_ir(), state=clean_state()).as_dict()
        second = render_routeros_pcc(ir=pcc_ir(), state=clean_state()).as_dict()
        self.assertEqual(first, second)

    def test_active_fasttrack_is_fail_closed(self):
        state = copy.deepcopy(clean_state())
        state["firewall"]["filter"].append(
            {".id": "*FT1", "chain": "forward", "action": "fasttrack-connection", "disabled": False}
        )
        with self.assertRaisesRegex(RouterOSPccRenderError, "FastTrack"):
            render_routeros_pcc(ir=pcc_ir(), state=state)

    def test_active_dstnat_is_fail_closed(self):
        state = copy.deepcopy(clean_state())
        state["firewall"]["nat"].append(
            {".id": "*DN1", "chain": "dstnat", "action": "dst-nat", "disabled": False}
        )
        with self.assertRaisesRegex(RouterOSPccRenderError, "dstnat"):
            render_routeros_pcc(ir=pcc_ir(), state=state)


if __name__ == "__main__":
    unittest.main()
