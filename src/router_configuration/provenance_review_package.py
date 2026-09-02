from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Any, Mapping


class ProvenanceReviewPackageError(ValueError):
    pass


_SHA256 = re.compile(r"^[0-9a-f]{64}$")


def _digest(value: Any, label: str) -> str:
    text = str(value or "").strip().lower()
    if not _SHA256.fullmatch(text):
        raise ProvenanceReviewPackageError(f"{label} must be a lowercase SHA-256 digest")
    return text


def _text(value: Any, label: str) -> str:
    text = str(value or "").strip()
    if not text:
        raise ProvenanceReviewPackageError(f"{label} must not be empty")
    if any(character in text for character in ("\n", "\r", "\x00")):
        raise ProvenanceReviewPackageError(f"{label} contains unsupported control characters")
    return text


@dataclass(frozen=True)
class ProvenanceReviewPackage:
    payload: Mapping[str, Any]

    def as_dict(self) -> dict[str, Any]:
        return dict(self.payload)


def prepare_chr_provenance_review_package(
    *,
    clean_readonly_summary: Mapping[str, Any],
) -> ProvenanceReviewPackage:
    """Prepare a non-attested operator review draft from accepted machine evidence.

    This function deliberately cannot convert machine evidence into operator
    attestation. It pre-binds immutable identifiers so an operator does not have
    to retype them, while every human-observation field remains false/null.
    """

    if clean_readonly_summary.get("schema_version") != "routeros-clean-readonly-summary/1":
        raise ProvenanceReviewPackageError("unsupported clean read-only evidence schema")

    technical = clean_readonly_summary.get("technical_admission")
    provenance = clean_readonly_summary.get("provenance")
    if not isinstance(technical, Mapping) or not isinstance(provenance, Mapping):
        raise ProvenanceReviewPackageError("clean evidence is missing admission/provenance state")
    if technical.get("ok") is not True or technical.get("claim") != "ready_for_operator_attestation":
        raise ProvenanceReviewPackageError("technical evidence is not ready for operator attestation")
    for field in (
        "acceptance_collection_write_operations_performed",
        "mutation_requests_attempted",
        "production_writer_available",
        "renderer_enabled",
        "write_authorized",
    ):
        if technical.get(field) is not False:
            raise ProvenanceReviewPackageError(f"technical evidence must keep {field}=false")
    if provenance.get("operator_attested") is not False:
        raise ProvenanceReviewPackageError("machine evidence must not already claim operator attestation")
    if provenance.get("automatic_target_matrix_admission") is not False:
        raise ProvenanceReviewPackageError("machine evidence must not auto-admit a target")

    target_id = _text(clean_readonly_summary.get("target"), "target")
    routeros_version = _text(clean_readonly_summary.get("routeros_version"), "routeros_version")
    state_sha = _digest(
        clean_readonly_summary.get("normalized_state_sha256"),
        "normalized_state_sha256",
    )
    artifact_digest = _text(clean_readonly_summary.get("artifact_digest"), "artifact_digest")
    if not artifact_digest.startswith("sha256:"):
        raise ProvenanceReviewPackageError("artifact_digest must be a sha256 reference")

    payload = {
        "schema_version": "routeros-provenance-attestation/1",
        "target_id": target_id,
        "target_kind": "routeros_chr",
        "evidence_origin": "live_chr",
        "source_evidence": {
            "workflow_sha": _text(clean_readonly_summary.get("workflow_sha"), "workflow_sha"),
            "workflow_run_id": int(clean_readonly_summary.get("workflow_run_id")),
            "artifact_id": int(clean_readonly_summary.get("artifact_id")),
            "artifact_digest": artifact_digest,
            "normalized_state_sha256": state_sha,
            "routeros_version": routeros_version,
        },
        "operator_attested": False,
        "controlled_environment": False,
        "write_operations_performed": False,
        "observed_at": None,
        "routeros_version": routeros_version,
        "normalized_state_sha256": state_sha,
        "review_required": [
            "operator directly observed the referenced controlled CHR run",
            "target identity and RouterOS version match the bound evidence",
            "normalized state digest matches the reviewed artifact",
            "no write operation occurred during the read-only acceptance collection",
        ],
        "candidate_review_complete": False,
        "automatic_target_matrix_admission": False,
        "write_authorized": False,
        "note": (
            "Machine-generated draft only. An operator must perform the review and explicitly "
            "attest the observed run before candidate review can proceed."
        ),
    }
    return ProvenanceReviewPackage(payload)
