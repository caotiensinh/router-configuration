"""Tamper-evident structural chain across Cisco C08, C09 and C10 artifacts.

This module verifies digest/identity continuity only. A structurally valid chain
is not proof that live evidence was accepted and never grants write authority.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass
import hashlib
import hmac
import json
from typing import Any, Mapping

from .transaction_execution_contract import CiscoRecoveryExecutionContract
from .validation_approval import CiscoApprovalBinding

_SHA256_LEN = 64


class CiscoEvidenceChainError(ValueError):
    """Raised when C08→C09→C10 structural evidence continuity fails."""


def _canonical_sha256(value: object) -> str:
    raw = json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False, default=str).encode("utf-8")
    return hashlib.sha256(raw).hexdigest()


def _is_sha256(value: object) -> bool:
    text = str(value or "")
    return len(text) == _SHA256_LEN and all(char in "0123456789abcdef" for char in text)


def _approval_digest(binding: CiscoApprovalBinding) -> str:
    unsigned = {
        "schema_version": "cisco-approval-binding/1",
        "change_id": binding.change_id,
        "target_id": binding.target_id,
        "pre_state_sha256": binding.pre_state_sha256,
        "payload_digest_sha256": binding.payload_digest_sha256,
        "schema_inventory_digest_sha256": binding.schema_inventory_digest_sha256,
        "catalog_digest_sha256": binding.catalog_digest_sha256,
        "validation_sha256": binding.validation_sha256,
        "model": binding.model,
        "iosxe_version": binding.iosxe_version,
        "documentation_train": binding.documentation_train,
        "platform_family": binding.platform_family,
        "role": binding.role,
        "feature_id": binding.feature_id,
        "target_datastore": binding.target_datastore,
    }
    return _canonical_sha256(unsigned)


def _validate_approval(binding: CiscoApprovalBinding) -> None:
    if not _is_sha256(binding.approval_sha256) or not hmac.compare_digest(binding.approval_sha256, _approval_digest(binding)):
        raise CiscoEvidenceChainError("C08 approval binding digest mismatch")
    if binding.approval_bound or binding.human_approved or binding.c08_complete:
        raise CiscoEvidenceChainError("C08 structural chain input must remain pre-write and incomplete")
    if binding.apply_authorized or binding.write_authorized or binding.production_write_authorized:
        raise CiscoEvidenceChainError("C08 structural chain input cannot carry write authority")


def _validate_c09_ingest(record: Mapping[str, Any]) -> None:
    if record.get("schema_version") != "cisco-c09-live-evidence-ingest/1":
        raise CiscoEvidenceChainError("unexpected C09 ingest schema")
    supplied = str(record.get("ingest_record_sha256", ""))
    unsigned = dict(record)
    unsigned.pop("ingest_record_sha256", None)
    expected = _canonical_sha256(unsigned)
    if not _is_sha256(supplied) or not hmac.compare_digest(supplied, expected):
        raise CiscoEvidenceChainError("C09 ingest record digest mismatch")
    if not _is_sha256(record.get("validated_bundle_sha256")):
        raise CiscoEvidenceChainError("C09 validated bundle digest missing")
    if record.get("repository_live_evidence_accepted") is not False or record.get("repository_c09_complete") is not False:
        raise CiscoEvidenceChainError("C09 ingest record cannot self-promote repository acceptance")
    for key in ("physical_hardware_claimed", "production_writer_available", "production_write_authorized"):
        if record.get(key) is not False:
            raise CiscoEvidenceChainError(f"C09 safety boundary must remain false: {key}")


def _validate_c10_contract(contract: CiscoRecoveryExecutionContract) -> None:
    payload = contract.as_dict()
    supplied = str(payload.pop("contract_sha256", ""))
    expected = _canonical_sha256(payload)
    if not _is_sha256(supplied) or not hmac.compare_digest(supplied, expected):
        raise CiscoEvidenceChainError("C10 execution contract digest mismatch")
    if contract.executor_implementation_present or contract.live_execution_observed or contract.live_rollback_observed:
        raise CiscoEvidenceChainError("C10 structural contract cannot claim live executor evidence")
    if contract.restored_state_verified or contract.c10_complete:
        raise CiscoEvidenceChainError("C10 structural contract cannot claim recovery completion")
    if contract.production_writer_available or contract.production_write_authorized:
        raise CiscoEvidenceChainError("C10 structural contract cannot carry production write authority")


@dataclass(frozen=True)
class CiscoEvidenceChain:
    target_id: str
    model: str
    iosxe_version: str
    c08_approval_sha256: str
    c09_ingest_record_sha256: str
    c09_validated_bundle_sha256: str
    c10_recovery_plan_sha256: str
    c10_execution_contract_sha256: str
    chain_sha256: str
    chain_structurally_valid: bool = True
    raw_c09_bundle_replayed: bool = False
    repository_live_evidence_accepted: bool = False
    c09_complete: bool = False
    c10_complete: bool = False
    physical_device_verified: bool = False
    production_writer_available: bool = False
    production_write_authorized: bool = False

    def as_dict(self) -> dict[str, Any]:
        payload = asdict(self)
        payload["schema_version"] = "cisco-evidence-chain/1"
        return payload


def build_structural_evidence_chain(*, approval: CiscoApprovalBinding, c09_ingest: Mapping[str, Any], c10_contract: CiscoRecoveryExecutionContract) -> CiscoEvidenceChain:
    """Verify structural continuity without elevating live-evidence acceptance."""

    _validate_approval(approval)
    _validate_c09_ingest(c09_ingest)
    _validate_c10_contract(c10_contract)

    identities = (
        (approval.target_id, c09_ingest.get("target_id"), c10_contract.target_id, "target"),
        (approval.model, c09_ingest.get("model"), c10_contract.model, "model"),
        (approval.iosxe_version, c09_ingest.get("iosxe_version"), c10_contract.iosxe_version, "IOS XE version"),
    )
    for c08_value, c09_value, c10_value, label in identities:
        if not (c08_value == c09_value == c10_value):
            raise CiscoEvidenceChainError(f"C08/C09/C10 {label} mismatch")

    if not hmac.compare_digest(approval.approval_sha256, c10_contract.approval_sha256):
        raise CiscoEvidenceChainError("C10 approval digest does not bind the C08 approval")
    c09_bundle = str(c09_ingest["validated_bundle_sha256"])
    if not hmac.compare_digest(c09_bundle, c10_contract.c09_bundle_sha256):
        raise CiscoEvidenceChainError("C10 recovery contract does not bind the C09 validated bundle")

    unsigned = {
        "schema_version": "cisco-evidence-chain/1",
        "target_id": approval.target_id,
        "model": approval.model,
        "iosxe_version": approval.iosxe_version,
        "c08_approval_sha256": approval.approval_sha256,
        "c09_ingest_record_sha256": c09_ingest["ingest_record_sha256"],
        "c09_validated_bundle_sha256": c09_bundle,
        "c10_recovery_plan_sha256": c10_contract.recovery_plan_sha256,
        "c10_execution_contract_sha256": c10_contract.contract_sha256,
        "chain_structurally_valid": True,
        "raw_c09_bundle_replayed": False,
        "repository_live_evidence_accepted": False,
        "c09_complete": False,
        "c10_complete": False,
        "physical_device_verified": False,
        "production_writer_available": False,
        "production_write_authorized": False,
    }
    return CiscoEvidenceChain(
        target_id=approval.target_id,
        model=approval.model,
        iosxe_version=approval.iosxe_version,
        c08_approval_sha256=approval.approval_sha256,
        c09_ingest_record_sha256=str(c09_ingest["ingest_record_sha256"]),
        c09_validated_bundle_sha256=c09_bundle,
        c10_recovery_plan_sha256=c10_contract.recovery_plan_sha256,
        c10_execution_contract_sha256=c10_contract.contract_sha256,
        chain_sha256=_canonical_sha256(unsigned),
    )
