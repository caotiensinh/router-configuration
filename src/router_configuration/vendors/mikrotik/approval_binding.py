from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass
from typing import Any, Mapping

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
    negative_control_rejected: bool = False
    configuration_unchanged: bool = False
    temporary_files_removed: bool = False

    @property
    def evidence_sha256(self) -> str:
        payload = {
            "script_sha256": self.script_sha256,
            "routeros_version": self.routeros_version,
            "passed": self.passed,
            "errors": list(self.errors),
            "negative_control_rejected": self.negative_control_rejected,
            "configuration_unchanged": self.configuration_unchanged,
            "temporary_files_removed": self.temporary_files_removed,
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


def dry_run_evidence_from_chr(
    *,
    result: Mapping[str, Any],
    script: MikroTikScriptArtifact,
) -> MikroTikDryRunEvidence:
    """Convert proven disposable-CHR dry-run output into approval evidence.

    This parser deliberately requires more than `ok=true`: the tested file hash
    must equal the exact compiled script, RouterOS must report a version, the
    negative control must be rejected, the configuration digest must remain
    unchanged, and temporary test files must be removed.
    """

    generated = result.get("generated_script")
    platform = result.get("platform")
    negative = result.get("negative_control")
    if not isinstance(generated, Mapping):
        raise MikroTikApprovalError("CHR dry-run evidence is missing generated_script")
    if not isinstance(platform, Mapping):
        raise MikroTikApprovalError("CHR dry-run evidence is missing platform")
    if not isinstance(negative, Mapping):
        raise MikroTikApprovalError("CHR dry-run evidence is missing negative_control")

    tested_sha = str(generated.get("sha256") or "").strip().lower()
    expected_sha = _require_hex64(script.script_sha256, "script.script_sha256")
    if tested_sha != expected_sha:
        raise MikroTikApprovalError("CHR dry-run tested a different .rsc script hash")

    version = str(platform.get("version") or "").strip()
    if not version:
        raise MikroTikApprovalError("CHR dry-run evidence is missing RouterOS version")

    passed = bool(result.get("ok")) and generated.get("dry_run_passed") is True
    negative_rejected = negative.get("dry_run_rejected") is True
    unchanged = result.get("configuration_changed") is False
    before = str(result.get("configuration_before_sha256") or "").strip()
    after = str(result.get("configuration_after_sha256") or "").strip()
    if not before or before != after:
        unchanged = False
    cleaned = result.get("temporary_files_removed") is True

    errors: list[str] = []
    if not passed:
        errors.append("generated script did not pass RouterOS import dry-run")
    if not negative_rejected:
        errors.append("RouterOS negative-control syntax fixture was not rejected")
    if not unchanged:
        errors.append("RouterOS configuration changed or state digests differ during dry-run")
    if not cleaned:
        errors.append("temporary RouterOS dry-run files were not removed")

    return MikroTikDryRunEvidence(
        script_sha256=tested_sha,
        routeros_version=version,
        passed=not errors,
        errors=tuple(errors),
        negative_control_rejected=negative_rejected,
        configuration_unchanged=unchanged,
        temporary_files_removed=cleaned,
    )


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
    if not dry_run.negative_control_rejected:
        raise MikroTikApprovalError("approval requires a proven rejected RouterOS dry-run negative control")
    if not dry_run.configuration_unchanged:
        raise MikroTikApprovalError("approval requires proof that RouterOS dry-run did not mutate configuration")
    if not dry_run.temporary_files_removed:
        raise MikroTikApprovalError("approval requires cleanup of temporary RouterOS dry-run files")

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
