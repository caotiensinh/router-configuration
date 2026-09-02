from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any, Mapping

from .acceptance_bundle import validate_readonly_acceptance_bundle
from .provenance import validate_provenance_attestation
from .target_admission import plan_target_matrix_admission


def _load_mapping(path: str | Path, label: str) -> Mapping[str, Any]:
    target = Path(path)
    try:
        payload = json.loads(target.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise ValueError(f"{label} could not be read as JSON: {exc.__class__.__name__}") from exc
    if not isinstance(payload, Mapping):
        raise ValueError(f"{label} must contain a JSON object")
    return payload


def review_candidate(
    *,
    profile_path: str | Path,
    evidence_path: str | Path,
    manifest_path: str | Path,
    attestation_path: str | Path,
    matrix_path: str | Path,
) -> dict[str, Any]:
    bundle = validate_readonly_acceptance_bundle(
        profile_path=profile_path,
        evidence_path=evidence_path,
        manifest_path=manifest_path,
    )
    if not bundle.ok:
        return {
            "ok": False,
            "stage": "bundle_integrity",
            "bundle": bundle.as_dict(),
            "matrix_mutated": False,
        }

    attestation = _load_mapping(attestation_path, "attestation")
    provenance = validate_provenance_attestation(
        bundle_result=bundle,
        attestation=attestation,
    )
    if not provenance.ok:
        return {
            "ok": False,
            "stage": "provenance",
            "bundle": bundle.as_dict(),
            "provenance": provenance.as_dict(),
            "matrix_mutated": False,
        }

    matrix = _load_mapping(matrix_path, "target matrix")
    admission = plan_target_matrix_admission(
        matrix=matrix,
        provenance=provenance,
        attestation=attestation,
    )
    return {
        "ok": admission.ok,
        "stage": "target_admission" if admission.ok else "target_admission_blocked",
        "bundle": bundle.as_dict(),
        "provenance": provenance.as_dict(),
        "admission": admission.as_dict(),
        "matrix_mutated": False,
    }


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="python -m router_configuration.review_candidate",
        description="Review RouterOS read-only evidence without mutating a router or target matrix",
    )
    parser.add_argument("--profile", required=True)
    parser.add_argument("--evidence", required=True)
    parser.add_argument("--manifest", required=True)
    parser.add_argument("--attestation", required=True)
    parser.add_argument("--matrix", default="ROUTEROS_TARGET_MATRIX.json")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        payload = review_candidate(
            profile_path=args.profile,
            evidence_path=args.evidence,
            manifest_path=args.manifest,
            attestation_path=args.attestation,
            matrix_path=args.matrix,
        )
    except ValueError as exc:
        payload = {
            "ok": False,
            "stage": "input_validation",
            "error": str(exc),
            "matrix_mutated": False,
        }
    print(json.dumps(payload, indent=2, sort_keys=True))
    return 0 if payload.get("ok") is True else 8


if __name__ == "__main__":
    raise SystemExit(main())
