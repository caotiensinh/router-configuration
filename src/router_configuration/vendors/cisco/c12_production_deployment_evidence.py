"""Fail-closed verification of externally produced Cisco C12 production evidence.

This module does not execute or authorize a production write. It validates an
immutable observation record proving that an already-authorized deployment was
executed, read back, verified, backed up, and bound to the exact C12 handover
manifest. Canonical C12 progress may only use a record produced from real
production evidence; synthetic unit fixtures are non-promoting.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import re
from typing import Any, Mapping

_SHA40_RE = re.compile(r"^[0-9a-f]{40}$")
_SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
_REF_RE = re.compile(r"^[A-Za-z0-9_.:@/-]{1,160}$")
_REQUIRED_TRUE = (
    "live_production_execution_observed",
    "production_authorization_validated",
    "apply_succeeded",
    "readback_verified",
    "desired_state_verified",
    "security_behavior_verified",
    "postchange_backup_verified",
    "rollback_available",
)
_REQUIRED_SHA256 = (
    "handover_manifest_sha256",
    "plan_sha256",
    "changeset_sha256",
    "production_authorization_attestation_sha256",
    "prechange_backup_sha256",
    "postchange_backup_sha256",
    "pre_state_sha256",
    "post_state_sha256",
    "execution_evidence_sha256",
    "verification_evidence_sha256",
)


class CiscoC12ProductionEvidenceError(ValueError):
    """Raised when C12 production deployment evidence is incomplete or unsafe."""


def _canonical_sha256(value: object) -> str:
    raw = json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()


def _sha256(value: object, label: str) -> str:
    text = str(value or "").strip().lower()
    if not _SHA256_RE.fullmatch(text):
        raise CiscoC12ProductionEvidenceError(f"{label} must be lowercase SHA-256")
    return text


def verify_c12_production_deployment_evidence(observation: Mapping[str, Any]) -> dict[str, Any]:
    """Validate one immutable externally produced production-deployment record."""

    if observation.get("schema_version") != "cisco-c12-production-deployment-observation/1":
        raise CiscoC12ProductionEvidenceError("unexpected C12 production observation schema")

    supplied = _sha256(observation.get("observation_sha256"), "observation_sha256")
    unsigned = dict(observation)
    unsigned.pop("observation_sha256", None)
    if not hmac.compare_digest(supplied, _canonical_sha256(unsigned)):
        raise CiscoC12ProductionEvidenceError("C12 production observation digest mismatch")

    deployment_id = str(observation.get("deployment_id", "")).strip()
    change_id = str(observation.get("change_id", "")).strip()
    authority_ref = str(observation.get("production_authority_ref", "")).strip()
    for value, label in (
        (deployment_id, "deployment_id"),
        (change_id, "change_id"),
        (authority_ref, "production_authority_ref"),
    ):
        if not _REF_RE.fullmatch(value):
            raise CiscoC12ProductionEvidenceError(f"invalid {label}")

    source_sha = str(observation.get("source_sha", "")).strip().lower()
    if not _SHA40_RE.fullmatch(source_sha):
        raise CiscoC12ProductionEvidenceError("source_sha must be an exact lowercase Git SHA")

    normalized_sha: dict[str, str] = {}
    for field in _REQUIRED_SHA256:
        normalized_sha[field] = _sha256(observation.get(field), field)

    for field in _REQUIRED_TRUE:
        if observation.get(field) is not True:
            raise CiscoC12ProductionEvidenceError(f"required production evidence claim is not verified: {field}")

    # The observation may prove that a specific historical deployment had valid
    # authorization. It must never grant reusable/future write authority.
    if observation.get("reusable_write_authority") is not False:
        raise CiscoC12ProductionEvidenceError("production observation cannot carry reusable write authority")
    if observation.get("physical_device_verified") is not True:
        raise CiscoC12ProductionEvidenceError("C12 production evidence requires prior physical verification")

    result: dict[str, Any] = {
        "schema_version": "cisco-c12-production-deployment-evidence/1",
        "deployment_id": deployment_id,
        "change_id": change_id,
        "source_sha": source_sha,
        "production_authority_ref": authority_ref,
        **normalized_sha,
        "live_production_execution_observed": True,
        "production_authorization_validated": True,
        "apply_succeeded": True,
        "readback_verified": True,
        "desired_state_verified": True,
        "security_behavior_verified": True,
        "postchange_backup_verified": True,
        "rollback_available": True,
        "physical_device_verified": True,
        "verified_production_deployment": True,
        "eligible_for_final_handover": True,
        "production_writer_available": False,
        "production_write_authorized": False,
        "observation_sha256": supplied,
    }
    result["verification_record_sha256"] = _canonical_sha256(result)
    return result
