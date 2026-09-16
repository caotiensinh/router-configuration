"""Fail-closed deterministic validator dispatch for Cisco C08.

The registry is intentionally transport-free. It only dispatches already
constructed candidate payloads to explicit per-feature validators and rejects
unknown features, duplicate registration, non-mapping results, and any validator
result that attempts to grant apply or production authority.
"""

from __future__ import annotations

import hashlib
import json
import re
from typing import Any, Callable, Mapping

_FEATURE_ID = re.compile(r"^[a-z][a-z0-9_.-]{2,95}$")
Validator = Callable[[Mapping[str, Any]], Mapping[str, Any]]


class CiscoC08ValidatorRegistryError(ValueError):
    pass


def _canonical_sha256(value: object) -> str:
    try:
        raw = json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True)
    except (TypeError, ValueError) as exc:
        raise CiscoC08ValidatorRegistryError("validator result must be canonical JSON data") from exc
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()


def build_validator_registry(entries: list[tuple[str, Validator]]) -> dict[str, Validator]:
    registry: dict[str, Validator] = {}
    for raw_feature_id, validator in entries:
        feature_id = str(raw_feature_id).strip()
        if not _FEATURE_ID.fullmatch(feature_id):
            raise CiscoC08ValidatorRegistryError("invalid feature id")
        if feature_id in registry:
            raise CiscoC08ValidatorRegistryError(f"duplicate validator registration: {feature_id}")
        if not callable(validator):
            raise CiscoC08ValidatorRegistryError(f"validator is not callable: {feature_id}")
        registry[feature_id] = validator
    if not registry:
        raise CiscoC08ValidatorRegistryError("validator registry must not be empty")
    return registry


def validate_with_registry(
    feature_id: str,
    payload: Mapping[str, Any],
    *,
    registry: Mapping[str, Validator],
) -> dict[str, Any]:
    feature = str(feature_id).strip()
    if not _FEATURE_ID.fullmatch(feature):
        raise CiscoC08ValidatorRegistryError("invalid feature id")
    validator = registry.get(feature)
    if validator is None:
        raise CiscoC08ValidatorRegistryError(f"no validator registered for feature: {feature}")
    if not callable(validator):
        raise CiscoC08ValidatorRegistryError(f"registered validator is not callable: {feature}")
    if not isinstance(payload, Mapping):
        raise CiscoC08ValidatorRegistryError("candidate payload must be a mapping")

    raw_result = validator(payload)
    if not isinstance(raw_result, Mapping):
        raise CiscoC08ValidatorRegistryError("validator result must be a mapping")
    result = dict(raw_result)
    for field in ("apply_authorized", "production_write_authorized"):
        if result.get(field) is True:
            raise CiscoC08ValidatorRegistryError(f"validator crossed pre-write boundary: {field}")

    record = {
        "schema_version": "cisco-c08-validator-dispatch/1",
        "feature_id": feature,
        "validation_result": result,
        "apply_authorized": False,
        "production_write_authorized": False,
    }
    record["dispatch_record_sha256"] = _canonical_sha256(record)
    return record
