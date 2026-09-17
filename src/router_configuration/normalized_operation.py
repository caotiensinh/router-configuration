from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass
from typing import Any, Mapping, Sequence

_ACTIONS = frozenset({"CREATE", "UPDATE", "DELETE", "NOOP", "READ_ONLY_CHECK"})
_ID = re.compile(r"^[A-Za-z0-9._:-]+$")
_FORBIDDEN_KEYS = frozenset({
    "command", "commands", "raw_cli", "api_path", "password", "token", "access_token",
    "refresh_token", "client_secret", "secret", "shared_secret", "private_key", "preshared_key", "psk",
})


class NormalizedOperationError(ValueError):
    pass


def _safe_text(value: Any, label: str) -> str:
    text = str(value or "").strip()
    if not text or any(c in text for c in ("\n", "\r", "\x00")):
        raise NormalizedOperationError(f"{label} must be a non-empty safe value")
    return text


def _reject_forbidden(value: Any, path: str) -> None:
    if isinstance(value, Mapping):
        for key, child in value.items():
            name = str(key).strip().lower()
            if name in _FORBIDDEN_KEYS:
                raise NormalizedOperationError(f"{path} contains forbidden field: {key}")
            _reject_forbidden(child, f"{path}.{key}")
    elif isinstance(value, (list, tuple)):
        for index, child in enumerate(value):
            _reject_forbidden(child, f"{path}[{index}]")


def _ids(values: Sequence[str], label: str) -> list[str]:
    result = [str(v).strip() for v in values]
    if any(not item or not _ID.fullmatch(item) for item in result):
        raise NormalizedOperationError(f"{label} contains invalid identifiers")
    if len(result) != len(set(result)):
        raise NormalizedOperationError(f"{label} must be unique")
    return sorted(result)


def _digest(payload: Mapping[str, Any]) -> str:
    raw = json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
    return hashlib.sha256(raw).hexdigest()


@dataclass(frozen=True)
class NormalizedOperation:
    payload: Mapping[str, Any]

    def as_dict(self) -> dict[str, Any]:
        return dict(self.payload)


def build_normalized_operation(
    *,
    operation_id: str,
    object_type: str,
    action: str,
    selector: Mapping[str, Any],
    desired_state: Mapping[str, Any],
    applicability: Mapping[str, Any],
    dependencies: Sequence[str],
    conflicts: Sequence[str],
    provenance: Mapping[str, Any],
    verification: Mapping[str, Any],
    rollback: Mapping[str, Any] | None = None,
) -> NormalizedOperation:
    op_id = _safe_text(operation_id, "operation_id")
    if not _ID.fullmatch(op_id):
        raise NormalizedOperationError("operation_id contains unsupported characters")
    obj_type = _safe_text(object_type, "object_type")
    action_name = _safe_text(action, "action").upper()
    if action_name not in _ACTIONS:
        raise NormalizedOperationError("unsupported action")
    if not isinstance(selector, Mapping) or not selector:
        raise NormalizedOperationError("selector must be a non-empty mapping")
    if not isinstance(desired_state, Mapping):
        raise NormalizedOperationError("desired_state must be a mapping")
    if not isinstance(applicability, Mapping) or not applicability:
        raise NormalizedOperationError("applicability must be explicit")
    if not isinstance(provenance, Mapping) or not provenance:
        raise NormalizedOperationError("provenance must be explicit")
    if not isinstance(verification, Mapping) or not verification:
        raise NormalizedOperationError("verification must be explicit")

    deps = _ids(dependencies, "dependencies")
    confs = _ids(conflicts, "conflicts")
    if op_id in deps or op_id in confs:
        raise NormalizedOperationError("operation cannot depend on or conflict with itself")
    if set(deps) & set(confs):
        raise NormalizedOperationError("dependency and conflict sets must be disjoint")

    mutating = action_name in {"CREATE", "UPDATE", "DELETE"}
    if mutating and (not isinstance(rollback, Mapping) or not rollback):
        raise NormalizedOperationError("mutating operation requires rollback metadata")
    if rollback is not None and not isinstance(rollback, Mapping):
        raise NormalizedOperationError("rollback must be a mapping")

    candidate = {
        "operation_id": op_id,
        "object_type": obj_type,
        "action": action_name,
        "selector": dict(selector),
        "desired_state": dict(desired_state),
        "applicability": dict(applicability),
        "dependencies": deps,
        "conflicts": confs,
        "provenance": dict(provenance),
        "verification": dict(verification),
        "rollback": dict(rollback or {}),
    }
    _reject_forbidden(candidate, "operation")

    payload = {
        "schema_version": "omada-normalized-operation/1",
        **candidate,
        "raw_cli_present": False,
        "invented_api_path_present": False,
        "production_write_authority": False,
    }
    payload["operation_sha256"] = _digest(payload)
    return NormalizedOperation(payload)
