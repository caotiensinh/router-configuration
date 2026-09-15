"""Integrity verifier for Cisco C06 normalized switch state.

This module verifies that a source-bound C06 normalized-state object still
matches its catalog and deterministic digest, including the OpenConfig trunk
contract flags. It does not promote synthetic observations to live C06 evidence.
"""

from __future__ import annotations

from dataclasses import asdict
import hashlib
import json

from .switch_state import SwitchNormalizedState, switch_state_catalog_digest


class CiscoSwitchStateIntegrityError(ValueError):
    """Raised when a C06 normalized state object fails integrity checks."""


def _canonical_sha256(value: object) -> str:
    raw = json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True)
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()


def verify_switch_state_integrity(state: SwitchNormalizedState) -> dict:
    if not isinstance(state, SwitchNormalizedState):
        raise CiscoSwitchStateIntegrityError("C06 state must be SwitchNormalizedState")
    if state.catalog_digest_sha256 != switch_state_catalog_digest():
        raise CiscoSwitchStateIntegrityError("C06 state is bound to a stale or different catalog")
    if state.c06_complete:
        raise CiscoSwitchStateIntegrityError("normalized state cannot self-assert C06 completion")
    if state.production_write_authorized or state.physical_device_verified:
        raise CiscoSwitchStateIntegrityError("C06 normalized state crossed the safety boundary")
    if state.c06_contract_complete != state.trunk_state_verified:
        raise CiscoSwitchStateIntegrityError("C06 trunk contract flags are inconsistent")

    payload = {
        "model": state.model,
        "iosxe_version": state.iosxe_version,
        "documentation_train": state.documentation_train,
        "platform_family": state.platform_family,
        "schema_inventory_digest_sha256": state.schema_inventory_digest_sha256,
        "observed_modules": state.observed_modules,
        "interfaces": [asdict(item) for item in state.interfaces],
        "vlans": [asdict(item) for item in state.vlans],
        "mac_entries": [asdict(item) for item in state.mac_entries],
        "stp_instances": [asdict(item) for item in state.stp_instances],
        "switched_vlans": [asdict(item) for item in state.switched_vlans],
        "trunk_state_verified": state.trunk_state_verified,
        "c06_contract_complete": state.c06_contract_complete,
        "c06_complete": False,
    }
    expected = _canonical_sha256(payload)
    if expected != state.state_digest_sha256:
        raise CiscoSwitchStateIntegrityError("C06 normalized-state digest mismatch")

    record = {
        "schema_version": "cisco-c06-state-integrity/1",
        "model": state.model,
        "iosxe_version": state.iosxe_version,
        "schema_inventory_digest_sha256": state.schema_inventory_digest_sha256,
        "catalog_digest_sha256": state.catalog_digest_sha256,
        "state_digest_sha256": state.state_digest_sha256,
        "interface_count": len(state.interfaces),
        "vlan_count": len(state.vlans),
        "mac_entry_count": len(state.mac_entries),
        "stp_instance_count": len(state.stp_instances),
        "switched_vlan_count": len(state.switched_vlans),
        "trunk_state_verified": state.trunk_state_verified,
        "normalized_state_integrity_valid": True,
        "live_state_observed": False,
        "repository_c06_complete": False,
        "production_write_authorized": False,
        "physical_device_verified": False,
    }
    record["integrity_record_sha256"] = _canonical_sha256(record)
    return record
