from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass
from typing import Any, Mapping, Sequence


class NormalizedOperationError(ValueError):
    pass


_ACTIONS = frozenset({"CREATE", "UPDATE", "DELETE", "NOOP", "READ_ONLY_CHECK"})
_FORBIDDEN_KEYS = frozenset({"command", "commands", "cli", "raw_cli", "api_path", "endpoint", "password", "token", "private_key", "secret"})
_SAFE_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{1,127}$")


def _digest(value: Any) -> str:
    raw = json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False, default=str).encode("utf-8")
    return hashlib.sha256(raw).hexdigest()


def _safe(value: object, label: str) -> str:
    text = str(value or "").strip()
    if not text or any(c in text for c in ("\n", "\r", "\x00")):
        raise NormalizedOperationError(f"{label} must be a non-empty safe value")
    return text


def _reject_forbidden(value: Any, path: str = "operation") -> None:
    if isinstance(value, Mapping):
        for key, child in value.items():
            name = str(key).strip().lower()
            if name in _FORBIDDEN_KEYS or any(marker in name for marker in ("password", "private_key", "client_secret", "access_token")):
                raise NormalizedOperationError(f"{path} contains forbidden executable/secret field: {key}")
            _reject_forbidden(child, f"{path}.{key}")
    elif isinstance(value, (list, tuple)):
        for index, child in enumerate(value):
            _reject_forbidden(child, f"{path}[{index}]")


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
    op_id = _safe(operation_id, "operation_id")
    if not _SAFE_ID.fullmatch(op_id):
        raise NormalizedOperationError("operation_id format is invalid")
    obj = _safe(object_type, "object_type")
    act = _safe(action, "action").upper()
    if act not in _ACTIONS:
        raise NormalizedOperationError("unsupported action")

    for label, value in {
        "selector": selector,
        "desired_state": desired_state,
        "applicability": applicability,
        "provenance": provenance,
        "verification": verification,
    }.items():
        if not isinstance(value, Mapping) or not value:
            raise NormalizedOperationError(f"{label} must be a non-empty mapping")
        _reject_forbidden(value, label)

    deps = [_safe(item, "dependency") for item in dependencies]
    confs = [_safe(item, "conflict") for item in conflicts]
    if len(deps) != len(set(deps)) or len(confs) != len(set(confs)):
        raise NormalizedOperationError("dependencies/conflicts must be unique")
    if op_id in deps or op_id in confs:
        raise NormalizedOperationError("operation cannot depend/conflict with itself")

    is_mutation = act in {"CREATE", "UPDATE", "DELETE"}
    if is_mutation and (not isinstance(rollback, Mapping) or not rollback):
        raise NormalizedOperationError("mutating action requires rollback metadata")
    if rollback is not None:
        _reject_forbidden(rollback, "rollback")

    payload: dict[str, Any] = {
        "schema_version": "omada-normalized-operation/1",
        "operation_id": op_id,
        "object_type": obj,
        "action": act,
        "selector": dict(selector),
        "desired_state": dict(desired_state),
        "applicability": dict(applicability),
        "dependencies": deps,
        "conflicts": confs,
        "provenance": dict(provenance),
        "verification": dict(verification),
        "rollback": dict(rollback or {}),
        "executable": False,
        "production_write_authority": False,
    }
    payload["operation_sha256"] = _digest(payload)
    return NormalizedOperation(payload)
