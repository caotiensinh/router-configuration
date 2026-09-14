from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from typing import Any

from ...governance import GovernanceAuthorization
from .approval_binding import MikroTikApprovalBinding, MikroTikApprovalError, validate_approval_fingerprint


class MikroTikExecutionGateError(ValueError):
    pass


def _sha256(payload: dict[str, Any]) -> str:
    raw = json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
    return hashlib.sha256(raw).hexdigest()


@dataclass(frozen=True)
class MikroTikExecutionGateProof:
    change_id: str
    approval_sha256: str
    master_rules_sha256: str
    agents_sha256: str
    governance_sha256: str
    mikrotik_vendor_rules_sha256: str
    proof_sha256: str

    def as_dict(self) -> dict[str, Any]:
        return {
            "schema_version": "mikrotik-execution-gate-proof/1",
            "claim": "governance_and_changeset_gates_passed_no_writer",
            "change_id": self.change_id,
            "approval_sha256": self.approval_sha256,
            "master_rules_sha256": self.master_rules_sha256,
            "agents_sha256": self.agents_sha256,
            "governance_sha256": self.governance_sha256,
            "mikrotik_vendor_rules_sha256": self.mikrotik_vendor_rules_sha256,
            "proof_sha256": self.proof_sha256,
            "governance_authorized": True,
            "changeset_approval_valid": True,
            "transport_present": False,
            "production_writer_available": False,
            "write_authorized": False,
        }


def _governance_payload(auth: GovernanceAuthorization) -> tuple[dict[str, Any], str]:
    if not auth.authorized_for_project_work or not auth.authorized_for_repository_write:
        raise MikroTikExecutionGateError("project governance is not authorized")
    if not auth.authorized_for_production_execution:
        raise MikroTikExecutionGateError(
            "production governance gate requires execution policy PASS and recorded human approval"
        )

    snapshot = auth.snapshot
    vendor_map = dict(snapshot.vendor_rule_sha256)
    vendor_path = "vendors/mikrotik/VENDOR_RULES.md"
    vendor_digest = vendor_map.get(vendor_path)
    if not vendor_digest:
        raise MikroTikExecutionGateError("current governance snapshot does not include MikroTik vendor rules")

    payload = {
        "schema_version": "project-governance-binding/1",
        "master_rules_sha256": snapshot.master_rules_sha256,
        "agents_sha256": snapshot.agents_sha256,
        "scoped_rule_sha256": [list(item) for item in snapshot.scoped_rule_sha256],
        "vendor_rule_sha256": [list(item) for item in snapshot.vendor_rule_sha256],
    }
    return payload, vendor_digest


def build_mikrotik_execution_gate_proof(
    *,
    binding: MikroTikApprovalBinding,
    approved_sha256: str,
    governance: GovernanceAuthorization,
) -> MikroTikExecutionGateProof:
    """Bind current project governance to one exact MikroTik changeset approval.

    This proof deliberately exposes no write transport. It is a prerequisite that
    a future production writer must require in addition to device/runtime safety
    gates. Passing it does not enable production mutation in the current project.
    """

    try:
        validate_approval_fingerprint(binding, approved_sha256)
    except MikroTikApprovalError as exc:
        raise MikroTikExecutionGateError("MikroTik changeset approval is invalid or stale") from exc

    governance_payload, vendor_digest = _governance_payload(governance)
    governance_digest = _sha256(governance_payload)
    payload = {
        "schema_version": "mikrotik-execution-gate-proof/1",
        "change_id": binding.change_id,
        "approval_sha256": binding.approval_sha256,
        "master_rules_sha256": governance.snapshot.master_rules_sha256,
        "agents_sha256": governance.snapshot.agents_sha256,
        "governance_sha256": governance_digest,
        "mikrotik_vendor_rules_sha256": vendor_digest,
        "transport_present": False,
        "production_writer_available": False,
        "write_authorized": False,
    }
    return MikroTikExecutionGateProof(
        change_id=binding.change_id,
        approval_sha256=binding.approval_sha256,
        master_rules_sha256=governance.snapshot.master_rules_sha256,
        agents_sha256=governance.snapshot.agents_sha256,
        governance_sha256=governance_digest,
        mikrotik_vendor_rules_sha256=vendor_digest,
        proof_sha256=_sha256(payload),
    )
