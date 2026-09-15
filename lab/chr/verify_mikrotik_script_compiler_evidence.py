from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path

from build_mikrotik_script_compiler_fixture import build_fixture
from router_configuration.vendors.mikrotik.approval_binding import (
    build_approval_binding,
    dry_run_evidence_from_chr,
    routeros_base_version,
)


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Bind MikroTik script-compiler semantic proof to live CHR dry-run evidence"
    )
    parser.add_argument("--script", required=True)
    parser.add_argument("--dry-run-evidence", required=True)
    parser.add_argument("--output", required=True)
    args = parser.parse_args()

    contract, proposal, artifact, semantic = build_fixture()
    script_path = Path(args.script)
    script_bytes = script_path.read_bytes()
    observed_script_sha256 = hashlib.sha256(script_bytes).hexdigest()
    if observed_script_sha256 != artifact.script_sha256:
        raise SystemExit(
            f"fixture script hash mismatch: expected={artifact.script_sha256} observed={observed_script_sha256}"
        )

    dry_run_payload = json.loads(Path(args.dry_run_evidence).read_text(encoding="utf-8"))
    dry_run = dry_run_evidence_from_chr(result=dry_run_payload, script=artifact)
    expected_base = routeros_base_version(contract.routeros_version)
    observed_base = dry_run.routeros_base_version
    if observed_base != expected_base:
        raise SystemExit(
            f"CHR RouterOS base version mismatch: expected={expected_base} observed={observed_base} raw={dry_run.routeros_version}"
        )

    pre_state_sha256 = str(dry_run_payload.get("configuration_before_sha256") or "").strip().lower()
    if len(pre_state_sha256) != 64:
        raise SystemExit("CHR dry-run evidence is missing a 64-character pre-state digest")

    binding = build_approval_binding(
        change_id="CHR-SCRIPT-COMPILER-ACCEPTANCE",
        routeros_version=contract.routeros_version,
        pre_state_sha256=pre_state_sha256,
        script=artifact,
        semantic_attestation=semantic,
        dry_run=dry_run,
    )
    result = {
        "schema_version": "mikrotik-script-compiler-chr-acceptance/1",
        "ok": True,
        "routeros_target_version": contract.routeros_version,
        "routeros_observed_version": dry_run.routeros_version,
        "routeros_base_version": observed_base,
        "command_count": len(contract.commands),
        "ordering_source": proposal.source,
        "script_sha256": artifact.script_sha256,
        "semantic_attestation_sha256": semantic.attestation_sha256,
        "dry_run_evidence_sha256": dry_run.evidence_sha256,
        "knowledge_sha256": binding.knowledge_sha256,
        "approval_sha256": binding.approval_sha256,
        "negative_control_rejected": dry_run.negative_control_rejected,
        "configuration_unchanged": dry_run.configuration_unchanged,
        "temporary_files_removed": dry_run.temporary_files_removed,
        "write_authorized": False,
    }
    output = Path(args.output)
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
