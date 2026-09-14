from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass
from typing import Any

from .knowledge import MikroTikOfflineKnowledge
from .script_planner import MikroTikScriptArtifact


class MikroTikApprovalError(ValueError):
    pass


_CHANGE_ID = re.compile(r"^[A-Za-z0-9_.:-]{1,96}$")
_HEX64 = re.compile(r"^[0-9a-f]{64}$")


@dataclass(frozen=True)
class MikroTikDryRunEvidence:
    script_sha256: str
    routeros_version: str
    passed: bool
    errors: tuple[str, ...] = ()

    @property
    def evidence_sha256(self) -> str:
        payload = {
            "script_sha256": self.script_sha256,
            "routeros_version": self.routeros_version,
            "passed": self.passed,
            "errors": list(self.errors),
        }
        raw = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")
        return hashlib.sha256(raw).hexdigest()


@dataclass(frozen=True)
class MikroTikApprovalBinding:
    change_id: str
    routeros_version: str
    pre_state_sha256: str
    render_sha256: str
    script_sha256: str
    knowledge_sha256: str
    dry_run_evidence_sha256: str
    ordered_command_ids: tuple[str, ...]
    approval_sha256: str

    def as_dict(self) -> dict[str, Any]:
        return {
            "schema_version": "mikrotik-approval-binding/1",
            "change_id": self.change_id,
            "routeros_version": self.routeros_version,
            "pre_state_sha256": self.pre_state_sha256,
            "render_sha256": self.render_sha256,
            "script_sha256": self.script_sha256,
            "knowledge_sha256": self.knowledge_sha256,
            "dry_run_evidence_sha256": self.dry_run_evidence_sha256,
            "ordered_command_ids": list(self.ordered_command_ids),
            "approval_sha256": self.approval_sha256,
            "write_authorized": False,
        }


def _require_hex64(value: str, label: str) -> str:
    normalized = value.strip().lower()
    if not _HEX64.fullmatch(normalized):
        raise MikroTikApprovalError(f"{label} must be a 64-character lowercase SHA-256 hex digest")
    return normalized


def _approval_digest(payload: dict[str, Any]) -> str:
    raw = json.dumps(
        payload,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
    ).encode("utf-8")
    return hashlib.sha256(raw).hexdigest()


def build_approval_binding(
    *,
    change_id: str,
    routeros_version: str,
    pre_state_sha256: str,
    script: MikroTikScriptArtifact,
    dry_run: MikroTikDryRunEvidence,
    knowledge: MikroTikOfflineKnowledge | None = None,
) -> MikroTikApprovalBinding:
    cid = change_id.strip()
    version = routeros_version.strip()
    if not _CHANGE_ID.fullmatch(cid):
        raise MikroTikApprovalError("change_id contains unsupported characters")
    if not version:
        raise MikroTikApprovalError("RouterOS version is required")
    pre_digest = _require_hex64(pre_state_sha256, "pre_state_sha256")
    script_digest = _require_hex64(script.script_sha256, "script_sha256")
    if script.write_authorized:
        raise MikroTikApprovalError("script artifact must remain generation-only before approval")
    if not script.dry_run_required:
        raise MikroTikApprovalError("MikroTik script artifact must require RouterOS dry-run")
    if dry_run.routeros_version.strip() != version:
        raise MikroTikApprovalError("dry-run RouterOS version does not match approval target")
    if dry_run.script_sha256.strip().lower() != script_digest:
        raise MikroTikApprovalError("dry-run evidence belongs to a different script")
    if not dry_run.passed or dry_run.errors:
        raise MikroTikApprovalError("RouterOS import dry-run must pass without errors before approval")

    store = knowledge or MikroTikOfflineKnowledge.bundled()
    payload = {
        "schema_version": "mikrotik-approval-binding/1",
        "change_id": cid,
        "routeros_version": version,
        "pre_state_sha256": pre_digest,
        "render_sha256": script.render_sha256,
        "script_sha256": script_digest,
        "knowledge_sha256": store.digest_sha256,
        "dry_run_evidence_sha256": dry_run.evidence_sha256,
        "ordered_command_ids": list(script.ordered_command_ids),
    }
    digest = _approval_digest(payload)
    return MikroTikApprovalBinding(
        change_id=cid,
        routeros_version=version,
        pre_state_sha256=pre_digest,
        render_sha256=script.render_sha256,
        script_sha256=script_digest,
        knowledge_sha256=store.digest_sha256,
        dry_run_evidence_sha256=dry_run.evidence_sha256,
        ordered_command_ids=script.ordered_command_ids,
        approval_sha256=digest,
    )


def validate_approval_fingerprint(
    binding: MikroTikApprovalBinding,
    approved_sha256: str,
) -> None:
    supplied = _require_hex64(approved_sha256, "approved_sha256")
    if supplied != binding.approval_sha256:
        raise MikroTikApprovalError(
            "approval fingerprint is stale or belongs to a different state/render/script/knowledge/dry-run set"
        )
