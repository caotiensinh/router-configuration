from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass
from typing import Any, Mapping, Sequence

_SHA1 = re.compile(r"^[0-9a-f]{40}$")
_SHA256 = re.compile(r"^[0-9a-f]{64}$")
_FORBIDDEN = frozenset({
    "password", "credential", "credentials", "credential_ref", "token", "access_token",
    "refresh_token", "client_secret", "secret", "shared_secret", "private_key",
    "preshared_key", "psk", "command", "commands", "shell", "transport", "writer",
})
_OUTCOMES = frozenset({"VERIFIED", "ROLLED_BACK_VERIFIED", "FAILED_UNRECOVERED", "CANCELLED_BEFORE_CHANGE"})


class ChangeRecordError(ValueError):
    pass


def _digest(value: Any) -> str:
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False, default=str).encode("utf-8")).hexdigest()


def _safe(value: Any, label: str) -> str:
    text = str(value or "").strip()
    if not text or any(c in text for c in ("\n", "\r", "\x00")):
        raise ChangeRecordError(f"{label} must be a non-empty safe value")
    return text


def _refs(values: Sequence[Any], label: str, *, allow_empty: bool = False) -> list[str]:
    out = [str(v).strip() for v in values]
    if not allow_empty and not out:
        raise ChangeRecordError(f"{label} must not be empty")
    if any(not item or any(c in item for c in ("\n", "\r", "\x00")) for item in out):
        raise ChangeRecordError(f"{label} contains an unsafe value")
    if len(out) != len(set(out)):
        raise ChangeRecordError(f"{label} must be unique")
    return out


def _reject_sensitive(value: Any, path: str = "change_record") -> None:
    if isinstance(value, Mapping):
        for key, child in value.items():
            name = str(key).strip().lower()
            if name in _FORBIDDEN or any(marker in name for marker in ("password", "private_key", "client_secret", "access_token", "refresh_token")):
                raise ChangeRecordError(f"{path} contains forbidden secret/runtime field: {key}")
            _reject_sensitive(child, f"{path}.{key}")
    elif isinstance(value, (list, tuple)):
        for index, child in enumerate(value):
            _reject_sensitive(child, f"{path}[{index}]")


@dataclass(frozen=True)
class ChangeRecord:
    payload: Mapping[str, Any]

    def as_dict(self) -> dict[str, Any]:
        return dict(self.payload)


def build_change_record(
    *,
    change_id: str,
    changeset_sha256: str,
    planned_main_sha: str,
    change_window: str,
    approval_evidence_ref: str,
    pre_change_evidence_refs: Sequence[str],
    post_change_evidence_refs: Sequence[str],
    outcome: str,
    rollback_evidence_refs: Sequence[str] = (),
    operator_note: str | None = None,
    ticket_ref: str | None = None,
    hardware_claim: bool = False,
    physical_evidence_refs: Sequence[str] = (),
) -> ChangeRecord:
    cid = _safe(change_id, "change_id")
    digest = str(changeset_sha256 or "").strip().lower()
    main_sha = str(planned_main_sha or "").strip().lower()
    if not _SHA256.fullmatch(digest):
        raise ChangeRecordError("changeset_sha256 must be a lowercase SHA-256")
    if not _SHA1.fullmatch(main_sha):
        raise ChangeRecordError("planned_main_sha must be a lowercase SHA-1")
    window = _safe(change_window, "change_window")
    approval = _safe(approval_evidence_ref, "approval_evidence_ref")
    pre_refs = _refs(pre_change_evidence_refs, "pre_change_evidence_refs")
    post_refs = _refs(post_change_evidence_refs, "post_change_evidence_refs", allow_empty=True)
    rollback_refs = _refs(rollback_evidence_refs, "rollback_evidence_refs", allow_empty=True)
    physical_refs = _refs(physical_evidence_refs, "physical_evidence_refs", allow_empty=True)

    state = str(outcome or "").strip().upper()
    if state not in _OUTCOMES:
        raise ChangeRecordError("outcome is not supported")
    if state == "VERIFIED" and not post_refs:
        raise ChangeRecordError("VERIFIED requires post-change evidence")
    if state == "ROLLED_BACK_VERIFIED" and not rollback_refs:
        raise ChangeRecordError("ROLLED_BACK_VERIFIED requires rollback evidence")
    if hardware_claim and not physical_refs:
        raise ChangeRecordError("hardware claim requires physical evidence")

    payload: dict[str, Any] = {
        "schema_version": "omada-change-record/1",
        "change_id": cid,
        "changeset_sha256": digest,
        "planned_main_sha": main_sha,
        "change_window": window,
        "approval_evidence_ref": approval,
        "pre_change_evidence_refs": pre_refs,
        "post_change_evidence_refs": post_refs,
        "rollback_evidence_refs": rollback_refs,
        "outcome": state,
        "hardware_claim": bool(hardware_claim),
        "physical_evidence_refs": physical_refs,
        "secret_material_included": False,
        "transport_present": False,
        "apply_available": False,
        "rollback_available": False,
        "production_writer_available": False,
        "write_authorized": False,
    }
    if operator_note is not None:
        payload["operator_note"] = _safe(operator_note, "operator_note")
    if ticket_ref is not None:
        payload["ticket_ref"] = _safe(ticket_ref, "ticket_ref")

    _reject_sensitive(payload)
    payload["change_record_sha256"] = _digest(payload)
    return ChangeRecord(payload)
