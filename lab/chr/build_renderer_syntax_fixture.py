from __future__ import annotations

import argparse
import json
from pathlib import Path

from router_configuration.routeros_renderer import RouterOSSafeSubsetRenderer
from router_configuration.safe_subset_ir import IntentOperation, IntentRisk, SafeSubsetIR


def build_syntax_fixture() -> dict[str, object]:
    """Build a secret-free CHR-only IR that exercises every v0.1 command template."""

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
                    "addressing": "lab",
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
                    "addressing": "lab",
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
        ),
    ).as_dict()
    plan = RouterOSSafeSubsetRenderer().render(ir).as_dict()
    if plan.get("complete") is not True or plan.get("blocked_operations") != []:
        raise RuntimeError("CHR syntax fixture must render a complete topology-only plan")
    if plan.get("transport_present") is not False or plan.get("write_authorized") is not False:
        raise RuntimeError("CHR syntax fixture renderer violated the generation-only boundary")
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
