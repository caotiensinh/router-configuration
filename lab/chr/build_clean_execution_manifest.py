from __future__ import annotations

import argparse
import json
from pathlib import Path


class CleanManifestError(RuntimeError):
    pass


def build_manifest(workflow_sha: str) -> dict[str, object]:
    workflow_sha = workflow_sha.strip().lower()
    if len(workflow_sha) != 40 or any(ch not in "0123456789abcdef" for ch in workflow_sha):
        raise CleanManifestError("workflow_sha must be a 40-character Git commit SHA")
    return {
        "schema_version": "routeros-clean-admission-execution/1",
        "phase": "clean_read_only_admission",
        "fresh_boot": True,
        "snapshot_mode": True,
        "fixture_population_performed": False,
        "acceptance_collection_write_operations_performed": False,
        "mutation_requests_attempted": False,
        "collection_http_methods": ["GET"],
        "prepared_context_setup_writes_preceded_phase": True,
        "workflow_sha": workflow_sha,
        "automatic_provenance_verification": False,
        "automatic_target_matrix_admission": False,
        "renderer_enabled": False,
        "write_authorized": False,
    }


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Build the fixed machine manifest for a clean read-only CHR admission phase"
    )
    parser.add_argument("--workflow-sha", required=True)
    parser.add_argument("--output", required=True)
    args = parser.parse_args()

    try:
        manifest = build_manifest(args.workflow_sha)
    except CleanManifestError as exc:
        print(json.dumps({"ok": False, "error": str(exc)}, sort_keys=True))
        return 13

    output = Path(args.output)
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(json.dumps({"ok": True, "output": str(output)}, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
