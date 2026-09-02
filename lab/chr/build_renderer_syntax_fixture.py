from __future__ import annotations

import argparse
import json
from pathlib import Path

from router_configuration.routeros_renderer import RouterOSSafeSubsetRenderer
from router_configuration.safe_subset_ir import IntentOperation, IntentRisk, SafeSubsetIR


KNOWN_PCC_BLOCKER = "routing.multiwan.capacity_weighted"


def build_syntax_fixture() -> dict[str, object]:
    """Build a secret-free CHR-only IR that exercises every current command template."""

    ir = SafeSubsetIR(
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
    plan = RouterOSSafeSubsetRenderer().render(ir).as_dict()

    blockers = plan.get("blocked_operations", [])
    blocker_ids = {
        str(item.get("operation_id"))
        for item in blockers
        if isinstance(item, dict)
    }
    if blocker_ids != {KNOWN_PCC_BLOCKER} or len(blockers) != 1:
        raise RuntimeError(
            "CHR syntax fixture permits exactly one known PCC-deferred blocker"
        )
    blocker_reason = str(blockers[0].get("reason") or "")
    if "PCC" not in blocker_reason:
        raise RuntimeError("CHR syntax fixture blocker must be the explicit PCC deferral")

    commands = plan.get("commands", [])
    sections = {
        str(item.get("section"))
        for item in commands
        if isinstance(item, dict)
    }
    required_sections = {
        "interface_list",
        "interface_list_member",
        "ip_address",
        "routing_table",
        "ip_route",
    }
    if sections != required_sections or len(commands) != 17:
        raise RuntimeError(
            f"CHR syntax fixture command coverage mismatch: sections={sorted(sections)} count={len(commands)}"
        )
    if plan.get("secret_references") != []:
        raise RuntimeError("CHR syntax fixture must remain secret-free")
    if plan.get("transport_present") is not False or plan.get("write_authorized") is not False:
        raise RuntimeError("CHR syntax fixture renderer violated the generation-only boundary")
    if plan.get("apply_available") is not False:
        raise RuntimeError("CHR syntax fixture must not expose an apply path")
    return plan


def main() -> int:
    parser = argparse.ArgumentParser(description="Build a secret-free RouterOS renderer syntax fixture")
    parser.add_argument("--script-output", required=True)
    parser.add_argument("--plan-output", required=True)
    args = parser.parse_args()

    plan = build_syntax_fixture()
    commands = plan.get("commands", [])
    script = "\n".join(str(item["command"]) for item in commands) + "\n"

    script_output = Path(args.script_output)
    plan_output = Path(args.plan_output)
    script_output.parent.mkdir(parents=True, exist_ok=True)
    plan_output.parent.mkdir(parents=True, exist_ok=True)
    script_output.write_text(script, encoding="utf-8")
    plan_output.write_text(json.dumps(plan, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(
        json.dumps(
            {
                "ok": True,
                "command_count": len(commands),
                "render_sha256": plan.get("render_sha256"),
                "script_output": str(script_output),
                "plan_output": str(plan_output),
                "known_deferred_blocker": KNOWN_PCC_BLOCKER,
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
