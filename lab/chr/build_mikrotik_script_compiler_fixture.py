from __future__ import annotations

import argparse
import json
from pathlib import Path

from router_configuration.vendors.mikrotik.script_planner import (
    build_script_contract,
    compile_script,
    deterministic_order,
)
from router_configuration.vendors.mikrotik.semantic_validation import attest_semantics


ROUTEROS_VERSION = "7.24.1"
RENDER_SHA256 = "7f73566c5ab65223bdf1732844a462f76ac0c9c38e934f2f89a55c5dbf26b861"


def build_fixture():
    render_plan = {
        "complete": True,
        "blocked_operations": [],
        "transport_present": False,
        "write_authorized": False,
        "render_sha256": RENDER_SHA256,
        "commands": [
            {
                "command_id": "interface-list.10.create",
                "section": "interface_list",
                "command": '/interface/list/add name="routercfg-script-compiler-lab" comment="routercfg:lab:script-compiler"',
                "risk": 20,
            },
            {
                "command_id": "interface-list.20.member",
                "section": "interface_list_member",
                "command": '/interface/list/member/add list="routercfg-script-compiler-lab" interface="ether2" comment="routercfg:lab:script-compiler"',
                "risk": 20,
            },
            {
                "command_id": "address.10.lab",
                "section": "ip_address",
                "command": '/ip/address/add address="198.18.250.1/30" interface="ether2" comment="routercfg:lab:script-compiler"',
                "risk": 30,
            },
        ],
    }
    contract = build_script_contract(render_plan=render_plan, routeros_version=ROUTEROS_VERSION)
    proposal = deterministic_order(contract)
    artifact = compile_script(
        contract=contract,
        proposal=proposal,
        file_name="routercfg-script-compiler-fixture.rsc",
    )
    semantic = attest_semantics(contract=contract, proposal=proposal, script=artifact)
    if not semantic.passed:
        raise RuntimeError(f"fixture semantic attestation failed: {semantic.as_dict()}")
    return contract, proposal, artifact, semantic


def main() -> int:
    parser = argparse.ArgumentParser(description="Build MikroTik AI-ordering script-compiler CHR fixture")
    parser.add_argument("--script-output", required=True)
    parser.add_argument("--metadata-output", required=True)
    args = parser.parse_args()

    contract, proposal, artifact, semantic = build_fixture()
    script_path = Path(args.script_output)
    metadata_path = Path(args.metadata_output)
    script_path.parent.mkdir(parents=True, exist_ok=True)
    metadata_path.parent.mkdir(parents=True, exist_ok=True)
    script_path.write_text(artifact.script, encoding="utf-8")
    payload = {
        "schema_version": "mikrotik-script-compiler-fixture/1",
        "routeros_version": contract.routeros_version,
        "contract": contract.model_payload(),
        "proposal": {
            "ordered_command_ids": list(proposal.ordered_command_ids),
            "source": proposal.source,
            "knowledge_ids": list(proposal.knowledge_ids),
        },
        "artifact": artifact.as_dict(),
        "semantic_attestation": semantic.as_dict(),
    }
    metadata_path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(json.dumps({
        "ok": True,
        "script_sha256": artifact.script_sha256,
        "semantic_attestation_sha256": semantic.attestation_sha256,
        "command_count": len(contract.commands),
        "raw_cli_exposed_to_model": contract.model_payload()["raw_routeros_cli_present"],
    }, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
