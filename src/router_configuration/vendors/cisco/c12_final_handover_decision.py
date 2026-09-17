"""Final C12 human handover decision bound to immutable deployment evidence.

This module cannot execute a production change and cannot grant reusable write
authority. It accepts or rejects final handover only after both the C12 handover
manifest and a verified production-deployment evidence record are cryptographically
bound to the same manifest.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import re
from typing import Any, Mapping

_SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
_REF_RE = re.compile(r"^[A-Za-z0-9_.:@/-]{1,160}$")
_DECISIONS = frozenset({"accept", "reject"})


class CiscoC12FinalHandoverDecisionError(ValueError):
    """Raised when final C12 handover evidence or authority fails closed."""


def _canonical_sha256(value: object) -> str:
    raw = json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()


def _sha256(value: object, label: str) -> str:
    text = str(value or "").strip().lower()
    if not _SHA256_RE.fullmatch(text):
        raise CiscoC12FinalHandoverDecisionError(f"{label} must be lowercase SHA-256")
    return text


def _verify_self_digest(record: Mapping[str, Any], field: str, label: str) -> str:
    supplied = _sha256(record.get(field), field)
    unsigned = dict(record)
    unsigned.pop(field, None)
    if not hmac.compare_digest(supplied, _canonical_sha256(unsigned)):
        raise CiscoC12FinalHandoverDecisionError(f"{label} digest mismatch")
    return supplied


def bind_c12_final_handover_decision(
    handover_manifest: Mapping[str, Any],
    production_evidence: Mapping[str, Any],
    *,
    decision_id: str,
    authority_ref: str,
    authority_attestation_sha256: str,
    decision: str,
) -> dict[str, Any]:
    """Bind a final human accept/reject decision to exact C12 evidence."""

    if handover_manifest.get("schema_version") != "cisco-c12-handover-manifest/1":
        raise CiscoC12FinalHandoverDecisionError("unexpected C12 handover manifest schema")
    manifest_sha = _verify_self_digest(handover_manifest, "manifest_sha256", "C12 handover manifest")
    if handover_manifest.get("ready_for_c12_human_review") is not True:
        raise CiscoC12FinalHandoverDecisionError("handover manifest is not ready for C12 human review")
    if handover_manifest.get("c12_complete") is not False:
        raise CiscoC12FinalHandoverDecisionError("handover manifest self-promoted C12 completion")
    if handover_manifest.get("production_writer_available") is not False:
        raise CiscoC12FinalHandoverDecisionError("handover manifest exposes a production writer")
    if handover_manifest.get("production_write_authorized") is not False:
        raise CiscoC12FinalHandoverDecisionError("handover manifest carries production write authority")

    if production_evidence.get("schema_version") != "cisco-c12-production-deployment-evidence/1":
        raise CiscoC12FinalHandoverDecisionError("unexpected C12 production evidence schema")
    evidence_sha = _verify_self_digest(
        production_evidence, "verification_record_sha256", "C12 production evidence"
    )
    if _sha256(production_evidence.get("handover_manifest_sha256"), "handover_manifest_sha256") != manifest_sha:
        raise CiscoC12FinalHandoverDecisionError("production evidence is not bound to this handover manifest")
    for field in (
        "verified_production_deployment",
        "eligible_for_final_handover",
        "physical_device_verified",
    ):
        if production_evidence.get(field) is not True:
            raise CiscoC12FinalHandoverDecisionError(f"production evidence is not final-handover eligible: {field}")
    if production_evidence.get("production_writer_available") is not False:
        raise CiscoC12FinalHandoverDecisionError("production evidence exposes a writer")
    if production_evidence.get("production_write_authorized") is not False:
        raise CiscoC12FinalHandoverDecisionError("production evidence carries reusable write authority")

    did = str(decision_id).strip()
    authority = str(authority_ref).strip()
    if not _REF_RE.fullmatch(did) or not _REF_RE.fullmatch(authority):
        raise CiscoC12FinalHandoverDecisionError("invalid final handover decision identity")
    attestation = _sha256(authority_attestation_sha256, "authority_attestation_sha256")
    normalized_decision = str(decision).strip().lower()
    if normalized_decision not in _DECISIONS:
        raise CiscoC12FinalHandoverDecisionError("unsupported final handover decision")

    accepted = normalized_decision == "accept"
    result = {
        "schema_version": "cisco-c12-final-handover-decision/1",
        "decision_id": did,
        "authority_ref": authority,
        "authority_attestation_sha256": attestation,
        "decision": normalized_decision,
        "handover_id": str(handover_manifest.get("handover_id", "")).strip(),
        "handover_manifest_sha256": manifest_sha,
        "production_deployment_evidence_sha256": evidence_sha,
        "deployment_id": str(production_evidence.get("deployment_id", "")).strip(),
        "change_id": str(production_evidence.get("change_id", "")).strip(),
        "verified_production_deployment": True,
        "physical_device_verified": True,
        "final_handover_accepted": accepted,
        "c12_complete": accepted,
        "production_writer_available": False,
        "production_write_authorized": False,
    }
    for field in ("handover_id", "deployment_id", "change_id"):
        if not _REF_RE.fullmatch(result[field]):
            raise CiscoC12FinalHandoverDecisionError(f"invalid bound identity: {field}")
    result["decision_record_sha256"] = _canonical_sha256(result)
    return result
