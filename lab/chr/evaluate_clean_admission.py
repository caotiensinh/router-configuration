from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any, Mapping

from router_configuration.routeros_state_contract import verify_routeros_discovery_evidence


POPULATION_MARKER = "routercfg-disposable-live-acceptance"
BOUNDARY_PROBE_MARKER = "routercfg-readonly-boundary-probe"
CLEAN_READER_POLICIES = frozenset({"read", "api", "rest-api"})


def _contains_marker(value: Any, marker: str) -> bool:
    if isinstance(value, Mapping):
        return any(
            _contains_marker(key, marker) or _contains_marker(item, marker)
            for key, item in value.items()
        )
    if isinstance(value, (list, tuple)):
        return any(_contains_marker(item, marker) for item in value)
    return marker in str(value)


def _policy_set(value: Any) -> set[str]:
    if isinstance(value, str):
        return {item.strip() for item in value.split(",") if item.strip()}
    if isinstance(value, (list, tuple, set, frozenset)):
        return {str(item).strip() for item in value if str(item).strip()}
    return set()


def evaluate_clean_admission(
    *,
    evidence: Mapping[str, Any],
    bootstrap: Mapping[str, Any],
    machine_provenance: Mapping[str, Any],
    execution_manifest: Mapping[str, Any],
) -> dict[str, Any]:
    """Evaluate Phase B: a fresh, technically read-only CHR admission boot.

    This evaluator never performs provenance attestation and never updates the
    target matrix. It only establishes whether evidence is technically ready
    for a human/operator provenance review.
    """

    errors: list[str] = []

    integrity = verify_routeros_discovery_evidence(evidence)
    if not integrity.ok:
        errors.extend(integrity.errors)

    collection = evidence.get("collection", {})
    if isinstance(collection, Mapping):
        if collection.get("failed_surfaces"):
            errors.append("clean admission discovery contains failed surfaces")
        if collection.get("missing_surfaces"):
            errors.append("clean admission discovery contains missing surfaces")

    if _contains_marker(evidence.get("normalized_state", {}), POPULATION_MARKER):
        errors.append("clean admission evidence contains populated-validation fixture objects")
    if _contains_marker(evidence.get("normalized_state", {}), BOUNDARY_PROBE_MARKER):
        errors.append("clean admission evidence contains reader-boundary probe objects")

    if bootstrap.get("ok") is not True:
        errors.append("secure prepared context did not report ok=true")
    reader = bootstrap.get("reader", {})
    if not isinstance(reader, Mapping):
        errors.append("clean admission reader summary is missing")
    else:
        declared_policy = _policy_set(reader.get("policy"))
        effective_policy = _policy_set(reader.get("effective_policy"))
        if declared_policy != CLEAN_READER_POLICIES:
            errors.append("clean admission declared reader policy is not the exact approved set")
        if effective_policy != CLEAN_READER_POLICIES:
            errors.append("clean admission effective reader policy is not the exact approved set")
    https = bootstrap.get("https", {})
    if not isinstance(https, Mapping) or https.get("certificate_verification") is not True:
        errors.append("clean admission must use certificate-verified HTTPS")
    if bootstrap.get("production_writer_available") is not False:
        errors.append("prepared context must not expose a production writer")

    platform = evidence.get("platform", {})
    bootstrap_platform = bootstrap.get("platform", {})
    if isinstance(platform, Mapping) and isinstance(bootstrap_platform, Mapping):
        if platform.get("version") != bootstrap_platform.get("version"):
            errors.append("prepared context RouterOS version does not match clean evidence")
        if platform.get("architecture") != bootstrap_platform.get("architecture"):
            errors.append("prepared context architecture does not match clean evidence")

    if machine_provenance.get("schema_version") != "routeros-ci-machine-provenance/1":
        errors.append("machine provenance schema is unsupported")
    if machine_provenance.get("claim") != "machine_observation_only":
        errors.append("machine provenance must remain machine_observation_only")
    if machine_provenance.get("operator_attested") is not False:
        errors.append("machine provenance must not claim operator attestation")
    if machine_provenance.get("automatic_target_matrix_admission") is not False:
        errors.append("machine provenance must not authorize target-matrix admission")
    if isinstance(platform, Mapping):
        if machine_provenance.get("routeros_version") != platform.get("version"):
            errors.append("machine provenance RouterOS version does not match clean evidence")
    if machine_provenance.get("normalized_state_sha256") != evidence.get("state_sha256"):
        errors.append("machine provenance state digest does not match clean evidence")

    if execution_manifest.get("schema_version") != "routeros-clean-admission-execution/1":
        errors.append("clean admission execution manifest schema is unsupported")
    if execution_manifest.get("phase") != "clean_read_only_admission":
        errors.append("execution manifest phase must be clean_read_only_admission")
    if execution_manifest.get("fresh_boot") is not True:
        errors.append("clean admission must use a fresh boot")
    if execution_manifest.get("snapshot_mode") is not True:
        errors.append("clean admission must run in snapshot mode")
    if execution_manifest.get("fixture_population_performed") is not False:
        errors.append("clean admission must not perform fixture population")
    if execution_manifest.get("acceptance_collection_write_operations_performed") is not False:
        errors.append("clean admission collection must perform zero write operations")
    if execution_manifest.get("mutation_requests_attempted") is not False:
        errors.append("clean admission phase must not attempt mutation requests")
    methods = execution_manifest.get("collection_http_methods")
    if methods != ["GET"]:
        errors.append("clean admission collection HTTP methods must be exactly ['GET']")
    if execution_manifest.get("prepared_context_setup_writes_preceded_phase") is not True:
        errors.append("manifest must explicitly separate prepared-context setup writes from admission phase")
    if execution_manifest.get("workflow_sha") != machine_provenance.get("workflow_sha"):
        errors.append("execution manifest workflow SHA does not match machine provenance")

    return {
        "ok": not errors,
        "phase": "clean_read_only_admission",
        "claim": "ready_for_operator_attestation" if not errors else "clean_admission_failed",
        "errors": errors,
        "routeros_version": platform.get("version") if isinstance(platform, Mapping) else None,
        "normalized_state_sha256": evidence.get("state_sha256"),
        "fixture_markers_absent": not (
            _contains_marker(evidence.get("normalized_state", {}), POPULATION_MARKER)
            or _contains_marker(evidence.get("normalized_state", {}), BOUNDARY_PROBE_MARKER)
        ),
        "reader_policy_verified": not errors
        and isinstance(reader, Mapping)
        and _policy_set(reader.get("policy")) == CLEAN_READER_POLICIES
        and _policy_set(reader.get("effective_policy")) == CLEAN_READER_POLICIES,
        "acceptance_collection_write_operations_performed": False,
        "eligible_for_operator_attestation": not errors,
        "automatic_provenance_verification": False,
        "automatic_target_matrix_admission": False,
        "renderer_enabled": False,
        "write_authorized": False,
    }


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Evaluate clean read-only CHR evidence before operator provenance attestation"
    )
    parser.add_argument("--evidence", required=True)
    parser.add_argument("--bootstrap", required=True)
    parser.add_argument("--machine-provenance", required=True)
    parser.add_argument("--execution-manifest", required=True)
    parser.add_argument("--output", required=True)
    args = parser.parse_args()

    evidence = json.loads(Path(args.evidence).read_text(encoding="utf-8"))
    bootstrap = json.loads(Path(args.bootstrap).read_text(encoding="utf-8"))
    machine = json.loads(Path(args.machine_provenance).read_text(encoding="utf-8"))
    manifest = json.loads(Path(args.execution_manifest).read_text(encoding="utf-8"))
    result = evaluate_clean_admission(
        evidence=evidence,
        bootstrap=bootstrap,
        machine_provenance=machine,
        execution_manifest=manifest,
    )

    output = Path(args.output)
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0 if result["ok"] else 12


if __name__ == "__main__":
    raise SystemExit(main())
