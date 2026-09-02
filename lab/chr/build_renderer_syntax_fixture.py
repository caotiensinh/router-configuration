from __future__ import annotations

import argparse
import json
from pathlib import Path

from router_configuration.routeros_pcc_renderer import render_routeros_pcc
from router_configuration.routeros_renderer import RouterOSSafeSubsetRenderer
from router_configuration.safe_subset_ir import IntentOperation, IntentRisk, SafeSubsetIR


KNOWN_PCC_BLOCKER = "routing.multiwan.capacity_weighted"
BASE_COMMAND_COUNT = 17
PCC_COMMAND_COUNT = 21
TOTAL_COMMAND_COUNT = BASE_COMMAND_COUNT + PCC_COMMAND_COUNT


def _build_ir() -> dict[str, object]:
    return SafeSubsetIR(
        device_id="chr-render-syntax-lab",
        operations=(
            IntentOperation(
                operation_id="topology.wan.lab-wan10g",
                feature="topology",
                resource="wan_role",
                attributes={
                    "name": "lab-wan10g",
                    "interface": "ether1",
                    "capacity_mbps": 10000,
                    "addressing": "static",
                    "address": "192.0.2.2/30",
                },
                risk=IntentRisk.MEDIUM,
                requires=("interfaces",),
            ),
            IntentOperation(
                operation_id="topology.wan.lab-wan1g",
                feature="topology",
                resource="wan_role",
                attributes={
                    "name": "lab-wan1g",
                    "interface": "ether2",
                    "capacity_mbps": 1000,
                    "addressing": "static",
                    "address": "198.51.100.2/30",
                },
                risk=IntentRisk.MEDIUM,
                requires=("interfaces",),
            ),
            IntentOperation(
                operation_id="topology.core",
                feature="topology",
                resource="core_uplink_role",
                attributes={"interface": "ether3", "capacity_mbps": 10000},
                risk=IntentRisk.MEDIUM,
                requires=("interfaces",),
            ),
            IntentOperation(
                operation_id=KNOWN_PCC_BLOCKER,
                feature="multiwan",
                resource="path_distribution_policy",
                attributes={
                    "mode": "capacity_weighted",
                    "weights": {"lab-wan10g": 10, "lab-wan1g": 1},
                    "failover": True,
                    "failback": "health_hysteresis",
                    "paths": {
                        "lab-wan10g": {
                            "interface": "ether1",
                            "addressing": "static",
                            "address": "192.0.2.2/30",
                            "gateway": "192.0.2.1",
                            "table": "to-lab-wan10g",
                            "failover_distance": 1,
                            "health_probe_targets": ["1.1.1.1", "8.8.8.8"],
                        },
                        "lab-wan1g": {
                            "interface": "ether2",
                            "addressing": "static",
                            "address": "198.51.100.2/30",
                            "gateway": "198.51.100.1",
                            "table": "to-lab-wan1g",
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


def _clean_pcc_state() -> dict[str, object]:
    return {
        "firewall": {
            "filter": [],
            "nat": [],
        }
    }


def build_syntax_fixture() -> dict[str, object]:
    """Build one secret-free CHR fixture covering recursive failover and PCC.

    The production safe-subset renderer still reports PCC as deferred because it
    does not yet consume live state. The isolated state-aware PCC renderer is
    therefore validated side-by-side in this CHR-only fixture. This is syntax
    evidence only and does not authorize production writes.
    """

    ir = _build_ir()
    base_plan = RouterOSSafeSubsetRenderer().render(ir).as_dict()

    blockers = base_plan.get("blocked_operations", [])
    blocker_ids = {
        str(item.get("operation_id"))
        for item in blockers
        if isinstance(item, dict)
    }
    if blocker_ids != {KNOWN_PCC_BLOCKER} or len(blockers) != 1:
        raise RuntimeError(
            "CHR syntax fixture permits exactly one production PCC-deferred blocker"
        )
    blocker_reason = str(blockers[0].get("reason") or "")
    if "PCC" not in blocker_reason:
        raise RuntimeError("CHR syntax fixture blocker must be the explicit PCC deferral")

    base_commands = base_plan.get("commands", [])
    base_sections = {
        str(item.get("section"))
        for item in base_commands
        if isinstance(item, dict)
    }
    required_base_sections = {
        "interface_list",
        "interface_list_member",
        "ip_address",
        "routing_table",
        "ip_route",
    }
    if base_sections != required_base_sections or len(base_commands) != BASE_COMMAND_COUNT:
        raise RuntimeError(
            f"CHR base renderer coverage mismatch: sections={sorted(base_sections)} count={len(base_commands)}"
        )

    pcc_plan = render_routeros_pcc(ir=ir, state=_clean_pcc_state()).as_dict()
    pcc_commands = pcc_plan.get("commands", [])
    pcc_sections = {
        str(item.get("section"))
        for item in pcc_commands
        if isinstance(item, dict)
    }
    if pcc_sections != {"pcc_policy_route", "firewall_mangle"}:
        raise RuntimeError(
            f"CHR PCC renderer coverage mismatch: sections={sorted(pcc_sections)}"
        )
    if len(pcc_commands) != PCC_COMMAND_COUNT:
        raise RuntimeError(
            f"CHR PCC renderer command count mismatch: {len(pcc_commands)}"
        )
    if pcc_plan.get("transport_present") is not False:
        raise RuntimeError("CHR PCC fixture must not contain a transport")
    if pcc_plan.get("apply_available") is not False:
        raise RuntimeError("CHR PCC fixture must not expose an apply path")
    if pcc_plan.get("write_authorized") is not False:
        raise RuntimeError("CHR PCC fixture must not authorize writes")

    combined_commands = [*base_commands, *pcc_commands]
    if len(combined_commands) != TOTAL_COMMAND_COUNT:
        raise RuntimeError("CHR combined syntax fixture command count mismatch")
    if base_plan.get("secret_references") != []:
        raise RuntimeError("CHR syntax fixture must remain secret-free")
    if base_plan.get("transport_present") is not False or base_plan.get("write_authorized") is not False:
        raise RuntimeError("CHR syntax fixture violated the generation-only boundary")
    if base_plan.get("apply_available") is not False:
        raise RuntimeError("CHR syntax fixture must not expose an apply path")

    return {
        "schema_version": "routeros-render-syntax-fixture/2",
        "claim": "combined_recursive_and_pcc_syntax_fixture",
        "base_renderer_plan": base_plan,
        "pcc_command_plan": pcc_plan,
        "commands": combined_commands,
        "command_count": len(combined_commands),
        "base_command_count": len(base_commands),
        "pcc_command_count": len(pcc_commands),
        "known_production_deferred_blocker": KNOWN_PCC_BLOCKER,
        "pcc_syntax_included": True,
        "secret_references": [],
        "transport_present": False,
        "apply_available": False,
        "write_authorized": False,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description="Build a secret-free RouterOS renderer syntax fixture")
    parser.add_argument("--script-output", required=True)
    parser.add_argument("--plan-output", required=True)
    args = parser.parse_args()

    fixture = build_syntax_fixture()
    commands = fixture.get("commands", [])
    script = "\n".join(str(item["command"]) for item in commands) + "\n"

    script_output = Path(args.script_output)
    plan_output = Path(args.plan_output)
    script_output.parent.mkdir(parents=True, exist_ok=True)
    plan_output.parent.mkdir(parents=True, exist_ok=True)
    script_output.write_text(script, encoding="utf-8")
    plan_output.write_text(json.dumps(fixture, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(
        json.dumps(
            {
                "ok": True,
                "command_count": len(commands),
                "base_command_count": fixture.get("base_command_count"),
                "pcc_command_count": fixture.get("pcc_command_count"),
                "script_output": str(script_output),
                "plan_output": str(plan_output),
                "known_production_deferred_blocker": KNOWN_PCC_BLOCKER,
                "pcc_syntax_included": True,
                "production_generation_gate_claimed": False,
                "write_authorized": False,
            },
            indent=2,
            sort_keys=True,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
