"""Deterministic completeness audit for the bounded Cisco C07 catalog.

The audit checks that the currently admitted desired-state slices remain exactly
the source-bound set and records known operations that remain deliberately
unadmitted. It never grants apply authority.
"""

from __future__ import annotations

import hashlib
import json
from typing import Any, Mapping

from .desired_state import load_desired_state_catalog

_EXPECTED_FEATURES = (
    "interface.description.set",
    "interface.mtu.set",
    "interface.shutdown.set",
)
_UNADMITTED = (
    "interface.shutdown.remove",
    "interface.ipv4.set",
    "switch.vlan.set",
)


class CiscoC07CompletenessAuditError(ValueError):
    """Raised when the C07 catalog drifts from the bounded source set."""


def _canonical_sha256(value: object) -> str:
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")).hexdigest()


def audit_c07_catalog(catalog: Mapping[str, Any]) -> dict[str, Any]:
    if catalog.get("vendor") != "Cisco" or catalog.get("os_family") != "IOS XE":
        raise CiscoC07CompletenessAuditError("C07 vendor/OS identity drift")
    if catalog.get("schema_version") != "cisco-iosxe-desired-state-catalog/3":
        raise CiscoC07CompletenessAuditError("unexpected C07 catalog schema")
    if set(catalog.get("documentation_trains", {})) != {"17.18", "26"}:
        raise CiscoC07CompletenessAuditError("C07 documentation train drift")

    features = catalog.get("features")
    if not isinstance(features, list) or any(not isinstance(item, Mapping) for item in features):
        raise CiscoC07CompletenessAuditError("C07 feature catalog is malformed")
    ids = tuple(sorted(str(item.get("id", "")) for item in features))
    expected = tuple(sorted(_EXPECTED_FEATURES))
    if ids != expected or len(ids) != len(set(ids)):
        raise CiscoC07CompletenessAuditError("C07 admitted feature set drift")

    for field in ("runtime_ai_rendering", "write_authorized", "production_write_authorized", "c07_complete"):
        if catalog.get(field) is not False:
            raise CiscoC07CompletenessAuditError(f"C07 safety boundary opened: {field}")

    result = {
        "schema_version": "cisco-c07-completeness-audit/1",
        "admitted_feature_ids": list(expected),
        "bounded_feature_count": len(expected),
        "unadmitted_operations": list(_UNADMITTED),
        "catalog_consistent": True,
        "c07_complete": False,
        "apply_authorized": False,
        "production_write_authorized": False,
    }
    result["audit_sha256"] = _canonical_sha256(result)
    return result


def audit_current_c07_catalog() -> dict[str, Any]:
    return audit_c07_catalog(load_desired_state_catalog())
