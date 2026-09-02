from __future__ import annotations

from copy import deepcopy
from dataclasses import dataclass
from typing import Any, Mapping

from .provenance import ProvenanceAdmissionResult


@dataclass(frozen=True)
class TargetAdmissionPlan:
    errors: tuple[str, ...]
    warnings: tuple[str, ...]
    target_id: str | None = None
    proposed_target: Mapping[str, Any] | None = None

    @property
    def ok(self) -> bool:
        return not self.errors

    def as_dict(self) -> dict[str, Any]:
        return {
            "ok": self.ok,
            "claim": "candidate_patch_only" if self.ok else "target_admission_blocked",
            "errors": list(self.errors),
            "warnings": list(self.warnings),
            "target_id": self.target_id,
            "proposed_target": dict(self.proposed_target or {}),
            "matrix_mutated": False,
            "manual_acceptance_required": True,
        }


def _targets_by_id(matrix: Mapping[str, Any]) -> dict[str, Mapping[str, Any]]:
    result: dict[str, Mapping[str, Any]] = {}
    targets = matrix.get("targets", [])
    if not isinstance(targets, list):
        return result
    for item in targets:
        if not isinstance(item, Mapping):
            continue
        target_id = str(item.get("id") or "").strip()
        if target_id:
            result[target_id] = item
    return result


def plan_target_matrix_admission(
    *,
    matrix: Mapping[str, Any],
    provenance: ProvenanceAdmissionResult,
    attestation: Mapping[str, Any],
) -> TargetAdmissionPlan:
    """Build a non-mutating target-matrix candidate patch.

    A successful plan is still not verified hardware evidence. It only proves
    that the candidate is structurally eligible for a human/lab acceptance
    decision. This function intentionally never mutates or writes the matrix.
    """

    errors: list[str] = []
    warnings: list[str] = []

    if matrix.get("schema_version") != "1.0":
        errors.append("unsupported RouterOS target matrix schema")

    if not provenance.ok:
        errors.append("provenance admission must pass before target-matrix planning")

    target_id = provenance.target_id
    target_kind = provenance.target_kind
    targets = _targets_by_id(matrix)
    current = targets.get(target_id or "")
    if current is None:
        errors.append("target_id is not declared in ROUTEROS_TARGET_MATRIX.json")
        return TargetAdmissionPlan(tuple(errors), tuple(warnings), target_id=target_id)

    current_kind = str(current.get("kind") or "")
    if current_kind != target_kind:
        errors.append(
            f"target kind mismatch: matrix={current_kind!r} provenance={target_kind!r}"
        )

    if current_kind == "synthetic_fixture":
        errors.append("synthetic fixture targets cannot receive live provenance admission")

    if current_kind == "physical_router":
        chr_target = targets.get("chr-live-v7")
        chr_status = str((chr_target or {}).get("status") or "")
        if chr_status != "verified_read_only":
            errors.append(
                "physical router admission is blocked until chr-live-v7 status is verified_read_only"
            )

    current_status = str(current.get("status") or "")
    if current_status.startswith("verified_"):
        warnings.append("target already has a verified status; candidate must not overwrite it automatically")

    if errors:
        return TargetAdmissionPlan(tuple(errors), tuple(warnings), target_id=target_id)

    proposed = deepcopy(dict(current))
    proposed["routeros_version"] = provenance.routeros_version
    proposed["status"] = "candidate_for_manual_acceptance"
    proposed["candidate_evidence"] = {
        "normalized_state_sha256": provenance.normalized_state_sha256,
        "observed_at": attestation.get("observed_at"),
        "evidence_origin": attestation.get("evidence_origin"),
        "controlled_environment": attestation.get("controlled_environment") is True,
        "write_operations_performed": attestation.get("write_operations_performed") is True,
    }
    proposed["manual_acceptance_required"] = True

    return TargetAdmissionPlan(
        errors=tuple(errors),
        warnings=tuple(warnings),
        target_id=target_id,
        proposed_target=proposed,
    )
