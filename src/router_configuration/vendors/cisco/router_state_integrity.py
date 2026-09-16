"""Integrity verifier for Cisco C05 normalized router state.

The C05 normalizer intentionally does not complete the live acceptance gate.
This module verifies that a normalized-state object has not been altered after
normalization and is still bound to the current source catalog. It produces a
review record only; it never promotes synthetic state to accepted C05 evidence.
"""

from __future__ import annotations

from dataclasses import asdict
import hashlib
import json

from .router_state import RouterNormalizedState, router_state_catalog_digest


class CiscoRouterStateIntegrityError(ValueError):
    """Raised when a C05 normalized state object fails integrity checks."""


def _canonical_sha256(value: object) -> str:
    raw = json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True)
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()


def verify_router_state_integrity(state: RouterNormalizedState) -> dict:
    if not isinstance(state, RouterNormalizedState):
        raise CiscoRouterStateIntegrityError("C05 state must be RouterNormalizedState")
    if state.catalog_digest_sha256 != router_state_catalog_digest():
        raise CiscoRouterStateIntegrityError("C05 state is bound to a stale or different catalog")
    if state.c05_complete:
        raise CiscoRouterStateIntegrityError("normalized state cannot self-assert C05 completion")
    if state.production_write_authorized or state.physical_device_verified:
        raise CiscoRouterStateIntegrityError("C05 normalized state crossed the safety boundary")

    payload = {
        "model": state.model,
        "iosxe_version": state.iosxe_version,
        "documentation_train": state.documentation_train,
        "platform_family": state.platform_family,
        "schema_inventory_digest_sha256": state.schema_inventory_digest_sha256,
        "observed_modules": state.observed_modules,
        "interfaces": [asdict(item) for item in state.interfaces],
        "routes": [asdict(item) for item in state.routes],
    }
    expected = _canonical_sha256(payload)
    if expected != state.state_digest_sha256:
        raise CiscoRouterStateIntegrityError("C05 normalized-state digest mismatch")

    record = {
        "schema_version": "cisco-c05-state-integrity/1",
        "model": state.model,
        "iosxe_version": state.iosxe_version,
        "schema_inventory_digest_sha256": state.schema_inventory_digest_sha256,
        "catalog_digest_sha256": state.catalog_digest_sha256,
        "state_digest_sha256": state.state_digest_sha256,
        "interface_count": len(state.interfaces),
        "route_count": len(state.routes),
        "normalized_state_integrity_valid": True,
        "live_state_observed": False,
        "repository_c05_complete": False,
        "production_write_authorized": False,
        "physical_device_verified": False,
    }
    record["integrity_record_sha256"] = _canonical_sha256(record)
    return record
