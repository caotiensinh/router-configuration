from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any, Mapping

from router_configuration.routeros_state_contract import verify_routeros_discovery_evidence

sys.path.insert(0, str(Path(__file__).resolve().parent))
from verify_populated_evidence import verify_populated_evidence  # noqa: E402


def evaluate(
    *,
    evidence: Mapping[str, Any],
    bootstrap: Mapping[str, Any],
    machine_provenance: Mapping[str, Any],
) -> dict[str, Any]:
    errors: list[str] = []

    integrity = verify_routeros_discovery_evidence(evidence)
    if not integrity.ok:
        errors.extend(integrity.errors)

    populated = verify_populated_evidence(evidence)
    if not populated["ok"]:
        errors.extend(populated["errors"])

    if bootstrap.get("ok") is not True:
        errors.append("secure bootstrap did not report ok=true")
    reader = bootstrap.get("reader", {})
    if not isinstance(reader, Mapping) or reader.get("policy") != "read,rest-api":
        errors.append("secure bootstrap reader policy must be exactly read,rest-api")
    https = bootstrap.get("https", {})
    if not isinstance(https, Mapping) or https.get("certificate_verification") is not True:
        errors.append("secure bootstrap must verify the HTTPS certificate")
    if bootstrap.get("production_writer_available") is not False:
        errors.append("secure bootstrap must not expose a production writer")

    evidence_platform = evidence.get("platform", {})
    bootstrap_platform = bootstrap.get("platform", {})
    if isinstance(evidence_platform, Mapping) and isinstance(bootstrap_platform, Mapping):
        if bootstrap_platform.get("version") != evidence_platform.get("version"):
            errors.append("bootstrap RouterOS version does not match discovery evidence")
        if bootstrap_platform.get("architecture") != evidence_platform.get("architecture"):
            errors.append("bootstrap architecture does not match discovery evidence")

    if machine_provenance.get("schema_version") != "routeros-ci-machine-provenance/1":
        errors.append("machine provenance schema is unsupported")
    if machine_provenance.get("claim") != "machine_observation_only":
        errors.append("machine provenance must remain a machine observation only")
    if machine_provenance.get("operator_attested") is not False:
        errors.append("machine provenance must not claim operator attestation")
    if machine_provenance.get("automatic_target_matrix_admission") is not False:
        errors.append("machine provenance must not authorize target-matrix admission")
    if machine_provenance.get("routeros_version") != evidence_platform.get("version"):
        errors.append("machine provenance RouterOS version does not match evidence")
    if machine_provenance.get("normalized_state_sha256") != evidence.get("state_sha256"):
        errors.append("machine provenance state digest does not match evidence")

    return {
        "ok": not errors,
        "claim": "ready_for_operator_attestation" if not errors else "technical_acceptance_failed",
        "errors": errors,
        "routeros_version": evidence_platform.get("version") if isinstance(evidence_platform, Mapping) else None,
        "normalized_state_sha256": evidence.get("state_sha256"),
        "populated_counts": populated.get("populated_counts", {}),
        "secret_boundary_verified": populated.get("secret_boundary_verified", False),
        "automatic_provenance_verification": False,
        "automatic_target_matrix_admission": False,
        "renderer_enabled": False,
        "write_authorized": False,
    }


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Evaluate disposable CHR technical acceptance before manual provenance attestation"
    )
    parser.add_argument("--evidence", required=True)
    parser.add_argument("--bootstrap", required=True)
    parser.add_argument("--machine-provenance", required=True)
    parser.add_argument("--output", required=True)
    args = parser.parse_args()

    evidence = json.loads(Path(args.evidence).read_text(encoding="utf-8"))
    bootstrap = json.loads(Path(args.bootstrap).read_text(encoding="utf-8"))
    machine = json.loads(Path(args.machine_provenance).read_text(encoding="utf-8"))
    result = evaluate(evidence=evidence, bootstrap=bootstrap, machine_provenance=machine)

    output = Path(args.output)
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0 if result["ok"] else 10


if __name__ == "__main__":
    raise SystemExit(main())
