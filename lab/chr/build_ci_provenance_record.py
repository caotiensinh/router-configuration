from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
from typing import Any, Mapping

from router_configuration.routeros_state_contract import verify_routeros_discovery_evidence


class MachineProvenanceError(RuntimeError):
    pass


def _parse_sha256_file(path: Path) -> str:
    text = path.read_text(encoding="utf-8").strip()
    parts = text.split()
    if not parts:
        raise MachineProvenanceError("download SHA256 file is empty")
    digest = parts[0].lower()
    if len(digest) != 64 or any(ch not in "0123456789abcdef" for ch in digest):
        raise MachineProvenanceError("download SHA256 file does not contain a valid SHA256 digest")
    return digest


def build_record(
    *,
    evidence: Mapping[str, Any],
    workflow_sha: str,
    image_url: str,
    image_zip_sha256: str,
) -> dict[str, Any]:
    verification = verify_routeros_discovery_evidence(evidence)
    if not verification.ok:
        raise MachineProvenanceError("discovery evidence failed integrity verification")

    workflow_sha = workflow_sha.strip().lower()
    if len(workflow_sha) != 40 or any(ch not in "0123456789abcdef" for ch in workflow_sha):
        raise MachineProvenanceError("workflow_sha must be a 40-character Git commit SHA")
    if not image_url.startswith("https://download.mikrotik.com/routeros/"):
        raise MachineProvenanceError("image_url must use the official MikroTik RouterOS download host")

    platform = evidence.get("platform", {})
    payload = {
        "schema_version": "routeros-ci-machine-provenance/1",
        "target_kind": "routeros_chr",
        "evidence_origin": "live_chr_ci",
        "workflow_sha": workflow_sha,
        "official_image_url": image_url,
        "official_image_zip_sha256": image_zip_sha256,
        "routeros_version": platform.get("version"),
        "architecture": platform.get("architecture"),
        "board_name": platform.get("board_name"),
        "normalized_state_sha256": evidence.get("state_sha256"),
        "evidence_schema_version": evidence.get("schema_version"),
        "operator_attested": False,
        "automatic_target_matrix_admission": False,
        "claim": "machine_observation_only",
    }
    canonical = json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
    payload["record_sha256"] = hashlib.sha256(canonical.encode("utf-8")).hexdigest()
    return payload


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Build a machine-only provenance record for disposable CHR CI evidence"
    )
    parser.add_argument("--evidence", required=True)
    parser.add_argument("--workflow-sha", required=True)
    parser.add_argument("--image-url", required=True)
    parser.add_argument("--image-sha256-file", required=True)
    parser.add_argument("--output", required=True)
    args = parser.parse_args()

    try:
        evidence = json.loads(Path(args.evidence).read_text(encoding="utf-8"))
        record = build_record(
            evidence=evidence,
            workflow_sha=args.workflow_sha,
            image_url=args.image_url,
            image_zip_sha256=_parse_sha256_file(Path(args.image_sha256_file)),
        )
    except (OSError, json.JSONDecodeError, MachineProvenanceError) as exc:
        print(json.dumps({"ok": False, "error": str(exc)}, sort_keys=True))
        return 7

    output = Path(args.output)
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(record, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(json.dumps({"ok": True, "output": str(output), "record_sha256": record["record_sha256"]}, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
