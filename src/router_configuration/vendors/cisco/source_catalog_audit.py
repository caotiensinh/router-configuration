"""Cross-catalog source and safety audit for Cisco IOS XE contracts.

The audit detects drift between C06 switch state, C07 desired state, and C11
physical read-only acceptance catalogs. It is read-only and cannot complete any
canonical stage.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass
import hashlib
import json
from typing import Mapping

from .desired_state import load_desired_state_catalog
from .physical_acceptance import load_physical_acceptance_catalog
from .switch_state import load_switch_state_catalog


class CiscoSourceCatalogAuditError(ValueError):
    """Raised when cross-catalog provenance or safety invariants drift."""


def _sha(value: object) -> str:
    raw = json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("utf-8")
    return hashlib.sha256(raw).hexdigest()


@dataclass(frozen=True)
class CiscoSourceCatalogAudit:
    vendor: str
    os_family: str
    documentation_trains: tuple[str, ...]
    yangmodels_commit: str
    desired_state_catalog_sha256: str
    switch_state_catalog_sha256: str
    physical_acceptance_catalog_sha256: str
    audit_sha256: str
    provenance_consistent: bool = True
    safety_boundaries_closed: bool = True
    c06_complete: bool = False
    c07_complete: bool = False
    c11_complete: bool = False
    physical_device_verified: bool = False
    production_write_authorized: bool = False

    def as_dict(self) -> dict:
        payload = asdict(self)
        payload["documentation_trains"] = list(self.documentation_trains)
        payload["schema_version"] = "cisco-source-catalog-audit/1"
        return payload


def _audit_catalogs(
    desired: Mapping[str, object],
    switch: Mapping[str, object],
    physical: Mapping[str, object],
) -> CiscoSourceCatalogAudit:
    identities = {(str(item.get("vendor")), str(item.get("os_family"))) for item in (desired, switch, physical)}
    if identities != {("Cisco", "IOS XE")}:
        raise CiscoSourceCatalogAuditError("Cisco catalog vendor/OS identity drift")

    desired_trains = desired.get("documentation_trains")
    switch_trains = switch.get("documentation_trains")
    if not isinstance(desired_trains, Mapping) or not isinstance(switch_trains, Mapping):
        raise CiscoSourceCatalogAuditError("documentation train metadata missing")
    if set(desired_trains) != {"17.18", "26"} or set(switch_trains) != {"17.18", "26"}:
        raise CiscoSourceCatalogAuditError("documentation train set drift")

    desired_provenance = desired.get("schema_provenance")
    switch_provenance = switch.get("schema_provenance")
    if not isinstance(desired_provenance, Mapping) or not isinstance(switch_provenance, Mapping):
        raise CiscoSourceCatalogAuditError("schema provenance missing")
    desired_commit = str(desired_provenance.get("yangmodels_commit", "")).lower()
    switch_commit = str(switch_provenance.get("yangmodels_commit", "")).lower()
    if not desired_commit or desired_commit != switch_commit:
        raise CiscoSourceCatalogAuditError("YangModels source pin drift between C06 and C07")

    false_invariants = (
        (desired, "runtime_ai_rendering"),
        (desired, "write_authorized"),
        (desired, "production_write_authorized"),
        (desired, "c07_complete"),
        (switch, "write_authorized"),
        (switch, "physical_device_verified"),
        (switch, "synthetic_fixture_can_complete_c06"),
        (physical, "synthetic_fixture_can_complete_c11"),
        (physical, "virtual_evidence_can_complete_c11"),
        (physical, "automatic_physical_device_verification"),
        (physical, "production_write_authorized"),
    )
    for catalog, key in false_invariants:
        if catalog.get(key) is not False:
            raise CiscoSourceCatalogAuditError(f"safety invariant drift: {key}")
    if physical.get("human_attestation_required") is not True or physical.get("read_only_required") is not True:
        raise CiscoSourceCatalogAuditError("C11 human/read-only boundary drift")
    if switch.get("live_state_evidence_required_for_c06") is not True:
        raise CiscoSourceCatalogAuditError("C06 live-state evidence gate drift")

    desired_sha = _sha(desired)
    switch_sha = _sha(switch)
    physical_sha = _sha(physical)
    unsigned = {
        "schema_version": "cisco-source-catalog-audit/1",
        "vendor": "Cisco",
        "os_family": "IOS XE",
        "documentation_trains": ["17.18", "26"],
        "yangmodels_commit": desired_commit,
        "desired_state_catalog_sha256": desired_sha,
        "switch_state_catalog_sha256": switch_sha,
        "physical_acceptance_catalog_sha256": physical_sha,
        "provenance_consistent": True,
        "safety_boundaries_closed": True,
        "c06_complete": False,
        "c07_complete": False,
        "c11_complete": False,
        "physical_device_verified": False,
        "production_write_authorized": False,
    }
    return CiscoSourceCatalogAudit(
        vendor="Cisco",
        os_family="IOS XE",
        documentation_trains=("17.18", "26"),
        yangmodels_commit=desired_commit,
        desired_state_catalog_sha256=desired_sha,
        switch_state_catalog_sha256=switch_sha,
        physical_acceptance_catalog_sha256=physical_sha,
        audit_sha256=_sha(unsigned),
    )


def audit_current_cisco_source_catalogs() -> CiscoSourceCatalogAudit:
    """Audit current packaged catalogs; never grants completion or write authority."""
    return _audit_catalogs(
        load_desired_state_catalog(),
        load_switch_state_catalog(),
        load_physical_acceptance_catalog(),
    )
