from __future__ import annotations

import re
from dataclasses import dataclass
from datetime import datetime
from typing import Any, Mapping

from .acceptance_bundle import AcceptanceBundleResult

_ALLOWED_TARGET_KINDS = {"routeros_chr", "physical_router"}
_ALLOWED_ORIGINS = {
    "routeros_chr": "live_chr",
    "physical_router": "physical_router",
}
_TARGET_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,62}[A-Za-z0-9]$|^[A-Za-z0-9]$")
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


@dataclass(frozen=True)
class ProvenanceAdmissionResult:
    errors: tuple[str, ...]
    warnings: tuple[str, ...]
    target_id: str | None = None
    target_kind: str | None = None
    routeros_version: str | None = None
    normalized_state_sha256: str | None = None

    @property
    def ok(self) -> bool:
        return not self.errors

    def as_dict(self) -> dict[str, Any]:
        return {
            "ok": self.ok,
            "claim": "eligible_for_target_matrix_review" if self.ok else "provenance_not_admissible",
            "errors": list(self.errors),
            "warnings": list(self.warnings),
            "target_id": self.target_id,
            "target_kind": self.target_kind,
            "routeros_version": self.routeros_version,
            "normalized_state_sha256": self.normalized_state_sha256,
            "automatic_provenance_verification": False,
        }


def _parse_timestamp(value: Any) -> bool:
    if not isinstance(value, str) or not value.strip():
        return False
    text = value.strip().replace("Z", "+00:00")
    try:
        parsed = datetime.fromisoformat(text)
    except ValueError:
        return False
    return parsed.tzinfo is not None


def _secret_like_paths(value: Any, path: str = "$") -> tuple[str, ...]:
    findings: list[str] = []
    if isinstance(value, Mapping):
        for raw_key, child in value.items():
            key = str(raw_key)
            lowered = key.lower()
            child_path = f"{path}.{key}"
            if any(token in lowered for token in _SENSITIVE_KEY_TOKENS):
                findings.append(child_path)
            findings.extend(_secret_like_paths(child, child_path))
    elif isinstance(value, (list, tuple)):
        for index, child in enumerate(value):
            findings.extend(_secret_like_paths(child, f"{path}[{index}]"))
    return tuple(findings)


def validate_provenance_attestation(
    *,
    bundle_result: AcceptanceBundleResult,
    attestation: Mapping[str, Any],
) -> ProvenanceAdmissionResult:
    """Validate a manual/lab provenance attestation for accepted evidence.

    This function never proves that a target is real. It only ensures that a
    human/lab provenance claim is explicit, internally consistent and cannot be
    confused with synthetic CI evidence. A successful result is eligible for
    review, not automatically accepted into the target matrix.
    """

    errors: list[str] = []
    warnings: list[str] = []

    if not bundle_result.ok:
        errors.append("candidate bundle must pass integrity validation before provenance review")

    if attestation.get("schema_version") != "routeros-provenance-attestation/1":
        errors.append("unsupported provenance attestation schema")

    sensitive_paths = _secret_like_paths(attestation)
    if sensitive_paths:
        errors.append(
            "provenance attestation must not contain secret-like fields: "
            + ", ".join(sensitive_paths)
        )

    target_id = str(attestation.get("target_id") or "").strip() or None
    target_kind = str(attestation.get("target_kind") or "").strip() or None
    evidence_origin = str(attestation.get("evidence_origin") or "").strip() or None

    if not target_id:
        errors.append("target_id is required")
    elif not _TARGET_ID.fullmatch(target_id):
        errors.append("target_id contains unsupported characters")
    if target_kind not in _ALLOWED_TARGET_KINDS:
        errors.append("target_kind must be routeros_chr or physical_router")
    elif evidence_origin != _ALLOWED_ORIGINS[target_kind]:
        errors.append(
            f"evidence_origin must be {_ALLOWED_ORIGINS[target_kind]!r} for target_kind {target_kind!r}"
        )

    if attestation.get("operator_attested") is not True:
        errors.append("operator_attested must be explicitly true")
    if attestation.get("controlled_environment") is not True:
        errors.append("controlled_environment must be explicitly true")
    if attestation.get("write_operations_performed") is not False:
        errors.append("read-only acceptance requires write_operations_performed=false")
    if not _parse_timestamp(attestation.get("observed_at")):
        errors.append("observed_at must be an offset-aware ISO-8601 timestamp")

    observed_version = str(attestation.get("routeros_version") or "").strip()
    if not observed_version:
        errors.append("routeros_version is required in provenance attestation")
    elif bundle_result.routeros_version and observed_version != bundle_result.routeros_version:
        errors.append("attested routeros_version does not match validated bundle")

    observed_state_sha = str(attestation.get("normalized_state_sha256") or "").strip()
    if not observed_state_sha:
        errors.append("normalized_state_sha256 is required in provenance attestation")
    elif (
        bundle_result.normalized_state_sha256
        and observed_state_sha != bundle_result.normalized_state_sha256
    ):
        errors.append("attested normalized_state_sha256 does not match validated bundle")

    if target_kind == "physical_router":
        model = str(attestation.get("model") or "").strip()
        if not model:
            errors.append("physical_router attestation requires model")
        platform = bundle_result.platform
        observed_board = (
            str(platform.get("board_name") or "").strip()
            if isinstance(platform, Mapping)
            else ""
        )
        if model and observed_board and model != observed_board:
            errors.append("attested physical-router model does not match validated bundle platform")

    note = str(attestation.get("note") or "").strip()
    if not note:
        warnings.append("provenance note is empty; record the lab/physical observation context")

    return ProvenanceAdmissionResult(
        errors=tuple(errors),
        warnings=tuple(warnings),
        target_id=target_id,
        target_kind=target_kind,
        routeros_version=bundle_result.routeros_version,
        normalized_state_sha256=bundle_result.normalized_state_sha256,
    )
