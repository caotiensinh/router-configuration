from __future__ import annotations

import argparse
import hashlib
import json
import re
from copy import deepcopy
from datetime import datetime
from pathlib import Path
from typing import Any, Mapping

_SHA256 = re.compile(r"^[0-9a-f]{64}$")
_GIT_SHA1 = re.compile(r"^[0-9a-f]{40}$")
_ALLOWED_REVIEW_MODES = {"preserved_evidence_review", "direct_live_observation"}
_REQUIRED_TRUE_FLAGS = (
    "clean_get_only_admission",
    "https_certificate_verification",
    "reader_write_denial_verified",
    "populated_high_value_surfaces_verified",
    "secret_boundary_verified",
)
_REQUIRED_FALSE_FLAGS = (
    "automatic_target_matrix_admission",
    "write_authorized",
    "physical_router_claimed",
    "production_write_authorized",
)
_SAFE_SECRET_METADATA_KEYS = {"secret_boundary_verified"}
_SENSITIVE_KEY_TOKENS = (
    "password",
    "passwd",
    "private_key",
    "private-key",
    "preshared_key",
    "preshared-key",
    "psk",
    "secret",
    "token",
    "credential",
)


class P07ReviewGateError(ValueError):
    pass


def _load_mapping(path: str | Path, label: str) -> Mapping[str, Any]:
    target = Path(path)
    try:
        payload = json.loads(target.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise P07ReviewGateError(
            f"{label} could not be read as JSON: {exc.__class__.__name__}"
        ) from exc
    if not isinstance(payload, Mapping):
        raise P07ReviewGateError(f"{label} must contain a JSON object")
    return payload


def _parse_offset_time(value: Any) -> bool:
    if not isinstance(value, str) or not value.strip():
        return False
    text = value.strip().replace("Z", "+00:00")
    try:
        parsed = datetime.fromisoformat(text)
    except ValueError:
        return False
    return parsed.tzinfo is not None


def _canonical_sha256(value: Mapping[str, Any]) -> str:
    encoded = json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
    ).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def _git_blob_sha1(raw: bytes) -> str:
    header = f"blob {len(raw)}\0".encode("ascii")
    return hashlib.sha1(header + raw).hexdigest()


def _secret_like_paths(value: Any, path: str = "$") -> tuple[str, ...]:
    findings: list[str] = []
    if isinstance(value, Mapping):
        for raw_key, child in value.items():
            key = str(raw_key)
            child_path = f"{path}.{key}"
            lowered = key.lower()
            if key not in _SAFE_SECRET_METADATA_KEYS and any(
                token in lowered for token in _SENSITIVE_KEY_TOKENS
            ):
                findings.append(child_path)
            findings.extend(_secret_like_paths(child, child_path))
    elif isinstance(value, (list, tuple)):
        for index, child in enumerate(value):
            findings.extend(_secret_like_paths(child, f"{path}[{index}]"))
    return tuple(findings)


def _target_by_id(matrix: Mapping[str, Any], target_id: str) -> Mapping[str, Any] | None:
    targets = matrix.get("targets")
    if not isinstance(targets, list):
        return None
    for item in targets:
        if isinstance(item, Mapping) and str(item.get("id") or "") == target_id:
            return item
    return None


def validate_p07_candidate(
    *,
    candidate: Mapping[str, Any],
    matrix: Mapping[str, Any],
    matrix_blob_sha: str,
    enforce_pending_matrix: bool = True,
) -> dict[str, Any]:
    errors: list[str] = []

    if candidate.get("schema_version") != "routeros-p07-candidate-review/2":
        errors.append("unsupported P07 candidate schema")

    challenge_id = str(candidate.get("candidate_review_challenge_sha256") or "").strip()
    binding_sha = str(candidate.get("challenge_payload_sha256") or "").strip()
    payload = candidate.get("challenge_payload")
    if not _SHA256.fullmatch(challenge_id):
        errors.append("candidate_review_challenge_sha256 must be a lowercase SHA-256 digest")
    if not _SHA256.fullmatch(binding_sha):
        errors.append("challenge_payload_sha256 must be a lowercase SHA-256 digest")
    if not isinstance(payload, Mapping):
        errors.append("challenge_payload must be a JSON object")
        payload = {}

    if payload:
        computed_binding = _canonical_sha256(payload)
        if binding_sha != computed_binding:
            errors.append("challenge_payload_sha256 does not match canonical challenge payload")

        if payload.get("challenge_schema") != "routeros-p07-readonly-review-challenge/1":
            errors.append("unsupported P07 challenge payload schema")
        if payload.get("target_id") != "chr-live-v7":
            errors.append("P07 challenge must target chr-live-v7")
        if payload.get("target_kind") != "routeros_chr":
            errors.append("P07 challenge target_kind must be routeros_chr")
        if payload.get("requested_promotion") != "verified_read_only":
            errors.append("P07 challenge may only request verified_read_only promotion")
        if not _GIT_SHA1.fullmatch(str(payload.get("technical_source_commit") or "")):
            errors.append("technical_source_commit must be a Git SHA-1")
        bound_matrix_blob = str(payload.get("target_matrix_blob_sha") or "")
        if not _GIT_SHA1.fullmatch(bound_matrix_blob):
            errors.append("target_matrix_blob_sha must be a Git blob SHA-1")
        elif enforce_pending_matrix and bound_matrix_blob != matrix_blob_sha:
            errors.append("candidate is stale for the current target-matrix blob")

        technical = payload.get("technical_acceptance")
        if not isinstance(technical, Mapping):
            errors.append("challenge payload is missing technical_acceptance")
        else:
            for field in _REQUIRED_TRUE_FLAGS:
                if technical.get(field) is not True:
                    errors.append(f"technical_acceptance.{field} must be true")
            for field in _REQUIRED_FALSE_FLAGS:
                if technical.get(field) is not False:
                    errors.append(f"technical_acceptance.{field} must be false")

        machine = payload.get("machine_evidence")
        if not isinstance(machine, Mapping):
            errors.append("challenge payload is missing machine_evidence")
        else:
            clean = machine.get("clean_readonly_admission")
            if not isinstance(clean, Mapping):
                errors.append("machine_evidence.clean_readonly_admission is required")
            else:
                if not _SHA256.fullmatch(str(clean.get("normalized_state_sha256") or "")):
                    errors.append("clean read-only normalized_state_sha256 is invalid")
                digest = str(clean.get("artifact_digest") or "")
                if not digest.startswith("sha256:") or not _SHA256.fullmatch(digest[7:]):
                    errors.append("clean read-only artifact_digest is invalid")

    if candidate.get("operator_attested") is not False:
        errors.append("candidate package must remain non-attested")
    if candidate.get("candidate_review_complete") is not False:
        errors.append("candidate package must remain incomplete until human review")
    for field in (
        "automatic_target_matrix_admission",
        "write_authorized",
        "physical_router_claimed",
        "production_write_authorized",
    ):
        if candidate.get(field) is not False:
            errors.append(f"candidate package must keep {field}=false")

    secret_paths = _secret_like_paths(candidate)
    if secret_paths:
        errors.append(
            "P07 candidate must not contain secret-like fields: " + ", ".join(secret_paths)
        )

    if matrix.get("schema_version") != "1.0":
        errors.append("unsupported RouterOS target matrix schema")
    current = _target_by_id(matrix, "chr-live-v7")
    if current is None:
        errors.append("chr-live-v7 is missing from target matrix")
    else:
        if current.get("kind") != "routeros_chr":
            errors.append("chr-live-v7 kind must remain routeros_chr")
        current_status = current.get("status")
        if enforce_pending_matrix:
            if current_status != "technical_readonly_validated_pending_attestation":
                errors.append("chr-live-v7 is not in the expected pending-attestation state")
        elif current_status not in {
            "technical_readonly_validated_pending_attestation",
            "verified_read_only",
        }:
            errors.append("chr-live-v7 has an unsupported P07 review state")
        if payload and current.get("routeros_version") != payload.get("routeros_version"):
            errors.append("candidate RouterOS version does not match target matrix")
        technical = current.get("technical_acceptance")
        if not isinstance(technical, Mapping) or technical.get("write_authorized") is not False:
            errors.append("target matrix must keep write_authorized=false")

    return {
        "ok": not errors,
        "claim": (
            "p07_candidate_bound_and_pending_human_attestation"
            if not errors
            else "p07_candidate_invalid"
        ),
        "errors": errors,
        "candidate_review_challenge_sha256": challenge_id or None,
        "challenge_payload_sha256": binding_sha or None,
        "matrix_mutated": False,
        "operator_attested": False,
        "write_authorized": False,
    }


def validate_p07_operator_attestation(
    *,
    candidate: Mapping[str, Any],
    attestation: Mapping[str, Any],
) -> dict[str, Any]:
    errors: list[str] = []
    payload = candidate.get("challenge_payload")
    if not isinstance(payload, Mapping):
        return {
            "ok": False,
            "errors": ["candidate challenge_payload is unavailable"],
            "write_authorized": False,
        }

    if attestation.get("schema_version") != "routeros-provenance-attestation/1":
        errors.append("unsupported operator attestation schema")
    if attestation.get("operator_attested") is not True:
        errors.append("operator_attested must be explicitly true")
    if attestation.get("decision") != "approve":
        errors.append("decision must be explicitly approve")
    if attestation.get("controlled_environment") is not True:
        errors.append("controlled_environment must be explicitly true")
    if attestation.get("write_operations_performed") is not False:
        errors.append("P07 read-only attestation requires write_operations_performed=false")
    if attestation.get("review_mode") not in _ALLOWED_REVIEW_MODES:
        errors.append("review_mode is unsupported")
    if attestation.get("direct_live_observation_claimed") not in (True, False):
        errors.append("direct_live_observation_claimed must be an explicit boolean")
    if not _parse_offset_time(attestation.get("observed_at")):
        errors.append("observed_at must be an offset-aware ISO-8601 timestamp")

    for field in (
        "write_authorized",
        "physical_router_claimed",
        "production_write_authorized",
    ):
        if attestation.get(field) is not False:
            errors.append(f"operator attestation must keep {field}=false")

    expected_challenge = candidate.get("candidate_review_challenge_sha256")
    expected_binding = candidate.get("challenge_payload_sha256")
    if attestation.get("candidate_review_challenge_sha256") != expected_challenge:
        errors.append("operator attestation does not match candidate review challenge")
    if attestation.get("challenge_payload_sha256") != expected_binding:
        errors.append("operator attestation does not match bound challenge payload")
    if attestation.get("target_id") != payload.get("target_id"):
        errors.append("operator attestation target_id does not match candidate")
    if attestation.get("target_kind") != payload.get("target_kind"):
        errors.append("operator attestation target_kind does not match candidate")
    if attestation.get("routeros_version") != payload.get("routeros_version"):
        errors.append("operator attestation RouterOS version does not match candidate")

    machine = payload.get("machine_evidence")
    clean = machine.get("clean_readonly_admission") if isinstance(machine, Mapping) else None
    state_sha = clean.get("normalized_state_sha256") if isinstance(clean, Mapping) else None
    if attestation.get("normalized_state_sha256") != state_sha:
        errors.append("operator attestation normalized_state_sha256 does not match candidate")

    secret_paths = _secret_like_paths(attestation)
    if secret_paths:
        errors.append(
            "operator attestation must not contain secret-like fields: "
            + ", ".join(secret_paths)
        )

    note = str(attestation.get("note") or "").strip()
    if not note:
        errors.append("operator attestation note must describe the review context")

    return {
        "ok": not errors,
        "claim": (
            "human_attestation_bound_to_p07_candidate"
            if not errors
            else "p07_human_attestation_invalid"
        ),
        "errors": errors,
        "candidate_review_challenge_sha256": expected_challenge,
        "challenge_payload_sha256": expected_binding,
        "write_authorized": False,
        "physical_router_claimed": False,
        "production_write_authorized": False,
    }


def plan_verified_read_only_promotion(
    *,
    candidate: Mapping[str, Any],
    attestation: Mapping[str, Any],
    matrix: Mapping[str, Any],
    matrix_blob_sha: str,
) -> dict[str, Any]:
    candidate_result = validate_p07_candidate(
        candidate=candidate,
        matrix=matrix,
        matrix_blob_sha=matrix_blob_sha,
    )
    if not candidate_result["ok"]:
        return {
            "ok": False,
            "stage": "candidate_validation",
            "candidate": candidate_result,
            "matrix_mutated": False,
            "write_authorized": False,
        }

    attestation_result = validate_p07_operator_attestation(
        candidate=candidate,
        attestation=attestation,
    )
    if not attestation_result["ok"]:
        return {
            "ok": False,
            "stage": "operator_attestation",
            "candidate": candidate_result,
            "attestation": attestation_result,
            "matrix_mutated": False,
            "write_authorized": False,
        }

    updated = deepcopy(dict(matrix))
    targets = updated.get("targets")
    if not isinstance(targets, list):
        raise P07ReviewGateError("target matrix targets must be a list")

    target = None
    for item in targets:
        if isinstance(item, dict) and item.get("id") == "chr-live-v7":
            target = item
            break
    if target is None:
        raise P07ReviewGateError("chr-live-v7 disappeared from target matrix")

    target["status"] = "verified_read_only"
    target["remaining_acceptance"] = []
    target["operator_review"] = {
        "candidate_review_challenge_sha256": candidate[
            "candidate_review_challenge_sha256"
        ],
        "challenge_payload_sha256": candidate["challenge_payload_sha256"],
        "review_mode": attestation["review_mode"],
        "direct_live_observation_claimed": attestation[
            "direct_live_observation_claimed"
        ],
        "observed_at": attestation["observed_at"],
        "decision": "approve",
        "operator_attested": True,
        "candidate_review_complete": True,
        "write_authorized": False,
        "physical_router_claimed": False,
        "production_write_authorized": False,
    }
    technical = target.setdefault("technical_acceptance", {})
    if not isinstance(technical, dict):
        raise P07ReviewGateError("chr-live-v7 technical_acceptance must be an object")
    technical["automatic_target_matrix_admission"] = False
    technical["write_authorized"] = False

    return {
        "ok": True,
        "stage": "verified_read_only_promotion_ready",
        "candidate": candidate_result,
        "attestation": attestation_result,
        "proposed_matrix": updated,
        "matrix_mutated": False,
        "manual_commit_required": True,
        "write_authorized": False,
        "physical_router_claimed": False,
        "production_write_authorized": False,
    }


def audit_verified_read_only_state(
    *,
    candidate: Mapping[str, Any],
    attestation: Mapping[str, Any],
    matrix: Mapping[str, Any],
    matrix_blob_sha: str,
) -> dict[str, Any]:
    candidate_result = validate_p07_candidate(
        candidate=candidate,
        matrix=matrix,
        matrix_blob_sha=matrix_blob_sha,
        enforce_pending_matrix=False,
    )
    attestation_result = validate_p07_operator_attestation(
        candidate=candidate,
        attestation=attestation,
    )
    errors: list[str] = []
    errors.extend(candidate_result.get("errors") or [])
    errors.extend(attestation_result.get("errors") or [])

    target = _target_by_id(matrix, "chr-live-v7")
    if target is None:
        errors.append("chr-live-v7 is missing from final target matrix")
    else:
        if target.get("status") != "verified_read_only":
            errors.append("final chr-live-v7 status must be verified_read_only")
        if target.get("remaining_acceptance") != []:
            errors.append("final chr-live-v7 remaining_acceptance must be empty")
        technical = target.get("technical_acceptance")
        if not isinstance(technical, Mapping):
            errors.append("final chr-live-v7 technical_acceptance is missing")
        else:
            if technical.get("automatic_target_matrix_admission") is not False:
                errors.append("final target must keep automatic_target_matrix_admission=false")
            if technical.get("write_authorized") is not False:
                errors.append("final target must keep write_authorized=false")

        review = target.get("operator_review")
        if not isinstance(review, Mapping):
            errors.append("final target is missing operator_review")
        else:
            expected = {
                "candidate_review_challenge_sha256": candidate.get(
                    "candidate_review_challenge_sha256"
                ),
                "challenge_payload_sha256": candidate.get("challenge_payload_sha256"),
                "review_mode": attestation.get("review_mode"),
                "direct_live_observation_claimed": attestation.get(
                    "direct_live_observation_claimed"
                ),
                "observed_at": attestation.get("observed_at"),
                "decision": "approve",
                "operator_attested": True,
                "candidate_review_complete": True,
                "write_authorized": False,
                "physical_router_claimed": False,
                "production_write_authorized": False,
            }
            for key, value in expected.items():
                if review.get(key) != value:
                    errors.append(f"final operator_review.{key} does not match attestation")

    return {
        "ok": not errors,
        "stage": (
            "verified_read_only_state_audited"
            if not errors
            else "verified_read_only_state_invalid"
        ),
        "errors": errors,
        "candidate": candidate_result,
        "attestation": attestation_result,
        "matrix_mutated": False,
        "write_authorized": False,
        "physical_router_claimed": False,
        "production_write_authorized": False,
    }


def review_files(
    *,
    candidate_path: str | Path,
    matrix_path: str | Path,
    attestation_path: str | Path | None = None,
) -> dict[str, Any]:
    candidate = _load_mapping(candidate_path, "P07 candidate")
    matrix_target = Path(matrix_path)
    try:
        matrix_raw = matrix_target.read_bytes()
        matrix = json.loads(matrix_raw.decode("utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise P07ReviewGateError(
            f"target matrix could not be read as JSON: {exc.__class__.__name__}"
        ) from exc
    if not isinstance(matrix, Mapping):
        raise P07ReviewGateError("target matrix must contain a JSON object")
    matrix_blob_sha = _git_blob_sha1(matrix_raw)

    if attestation_path is None:
        return validate_p07_candidate(
            candidate=candidate,
            matrix=matrix,
            matrix_blob_sha=matrix_blob_sha,
        )

    attestation = _load_mapping(attestation_path, "operator attestation")
    current = _target_by_id(matrix, "chr-live-v7")
    current_status = str((current or {}).get("status") or "")
    if current_status == "verified_read_only":
        return audit_verified_read_only_state(
            candidate=candidate,
            attestation=attestation,
            matrix=matrix,
            matrix_blob_sha=matrix_blob_sha,
        )
    return plan_verified_read_only_promotion(
        candidate=candidate,
        attestation=attestation,
        matrix=matrix,
        matrix_blob_sha=matrix_blob_sha,
    )


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="python -m router_configuration.p07_review_gate",
        description=(
            "Validate the hash-bound P07 RouterOS CHR read-only review candidate "
            "and, when a genuine operator attestation is supplied, plan the "
            "verified_read_only matrix promotion without writing files."
        ),
    )
    parser.add_argument(
        "--candidate",
        default="evidence/chr/p07-readonly-candidate-review.json",
    )
    parser.add_argument("--matrix", default="ROUTEROS_TARGET_MATRIX.json")
    parser.add_argument(
        "--attestation",
        help="operator attestation JSON; omit to validate the pending candidate only",
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        result = review_files(
            candidate_path=args.candidate,
            matrix_path=args.matrix,
            attestation_path=args.attestation,
        )
    except P07ReviewGateError as exc:
        result = {
            "ok": False,
            "stage": "input_validation",
            "error": str(exc),
            "matrix_mutated": False,
            "write_authorized": False,
        }
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0 if result.get("ok") is True else 12


if __name__ == "__main__":
    raise SystemExit(main())
