"""Fail-closed contract for human-attested physical IOS XE read-only evidence.

This module validates sanitized evidence metadata only. Unit tests and synthetic
fixtures can exercise the validator, but cannot complete C11 or assert that a
physical device was actually observed.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass
import hashlib
from importlib import resources
import json
import re
from typing import Mapping

from .platforms import assess_read_only_candidate

_SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
_GIT_SHA_RE = re.compile(r"^[0-9a-f]{40}$")
_ALLOWED_TARGET_KINDS = frozenset({"physical_router", "physical_switch"})
_ALLOWED_TRANSPORTS = frozenset({"netconf", "restconf"})
_VIRTUAL_PLATFORM_FAMILIES = frozenset({"Catalyst 8000V"})


class CiscoPhysicalAcceptanceError(ValueError):
    """Raised when a physical-evidence claim violates the C11 contract."""


@dataclass(frozen=True)
class PhysicalReadOnlyEvidenceClaim:
    target_kind: str
    model: str
    iosxe_version: str
    platform_family: str
    role: str
    transport: str
    source_sha: str
    schema_inventory_digest_sha256: str
    observation_digest_sha256: str
    target_identity_digest_sha256: str
    human_attestation_digest_sha256: str
    contract_digest_sha256: str
    evidence_origin: str = "operator_attested_physical_iosxe"
    read_only: bool = True
    write_attempted: bool = False
    virtualization: bool = False
    eligible_for_human_acceptance: bool = True
    synthetic_fixture_can_complete_c11: bool = False
    c11_complete: bool = False
    physical_device_verified: bool = False
    production_write_authorized: bool = False

    def to_dict(self) -> dict:
        return asdict(self)


def _canonical_sha256(value: object) -> str:
    canonical = json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True)
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def load_physical_acceptance_catalog() -> dict:
    package = resources.files("router_configuration.vendors.cisco.data")
    catalog = json.loads(package.joinpath("physical_acceptance_catalog.json").read_text(encoding="utf-8"))
    _validate_catalog(catalog)
    return catalog


def physical_acceptance_catalog_digest() -> str:
    return _canonical_sha256(load_physical_acceptance_catalog())


def _validate_catalog(catalog: Mapping[str, object]) -> None:
    if catalog.get("schema_version") != "cisco-iosxe-physical-readonly-acceptance/1":
        raise CiscoPhysicalAcceptanceError("unsupported C11 physical acceptance catalog schema")
    if catalog.get("vendor") != "Cisco" or catalog.get("os_family") != "IOS XE":
        raise CiscoPhysicalAcceptanceError("C11 vendor/OS mismatch")
    if set(catalog.get("target_kinds", [])) != _ALLOWED_TARGET_KINDS:
        raise CiscoPhysicalAcceptanceError("C11 target kind set mismatch")
    if set(catalog.get("transports", [])) != _ALLOWED_TRANSPORTS:
        raise CiscoPhysicalAcceptanceError("C11 transport set mismatch")
    for key in (
        "synthetic_fixture_can_complete_c11",
        "virtual_evidence_can_complete_c11",
        "automatic_physical_device_verification",
        "production_write_authorized",
    ):
        if catalog.get(key) is not False:
            raise CiscoPhysicalAcceptanceError(f"C11 safety boundary must remain false: {key}")
    if catalog.get("human_attestation_required") is not True:
        raise CiscoPhysicalAcceptanceError("C11 must require human attestation")
    if catalog.get("read_only_required") is not True:
        raise CiscoPhysicalAcceptanceError("C11 must remain read-only")


def _digest(value: object, field: str) -> str:
    text = str(value).strip().lower()
    if not _SHA256_RE.fullmatch(text):
        raise CiscoPhysicalAcceptanceError(f"valid sha256 digest required: {field}")
    return text


def validate_physical_readonly_claim(
    *,
    target_kind: str,
    model: str,
    iosxe_version: str,
    transport: str,
    source_sha: str,
    schema_inventory_digest_sha256: str,
    observation_digest_sha256: str,
    target_identity_digest_sha256: str,
    human_attestation_digest_sha256: str,
    evidence_origin: str,
    human_attested: bool,
    read_only: bool,
    write_attempted: bool,
    virtualization: bool,
) -> PhysicalReadOnlyEvidenceClaim:
    """Validate sanitized metadata for a possible C11 human acceptance review."""

    catalog = load_physical_acceptance_catalog()
    kind = str(target_kind).strip().lower()
    if kind not in _ALLOWED_TARGET_KINDS:
        raise CiscoPhysicalAcceptanceError("target_kind must identify physical router or switch")

    decision = assess_read_only_candidate(model, iosxe_version)
    if not decision.read_only_candidate or decision.role is None:
        raise CiscoPhysicalAcceptanceError(f"platform/version not admitted: {decision.status}")
    if decision.family in _VIRTUAL_PLATFORM_FAMILIES:
        raise CiscoPhysicalAcceptanceError("virtual platform family cannot satisfy physical evidence")
    expected_role = "router" if kind == "physical_router" else "switch"
    if decision.role.value != expected_role:
        raise CiscoPhysicalAcceptanceError("physical target kind conflicts with admitted device role")

    transport_value = str(transport).strip().lower()
    if transport_value not in _ALLOWED_TRANSPORTS:
        raise CiscoPhysicalAcceptanceError("unsupported C11 read-only transport")

    commit_sha = str(source_sha).strip().lower()
    if not _GIT_SHA_RE.fullmatch(commit_sha):
        raise CiscoPhysicalAcceptanceError("exact 40-character source SHA is required")

    if evidence_origin != "operator_attested_physical_iosxe":
        raise CiscoPhysicalAcceptanceError("physical evidence origin must be operator-attested")
    if human_attested is not True:
        raise CiscoPhysicalAcceptanceError("human attestation is required for physical evidence")
    if read_only is not True or write_attempted is not False:
        raise CiscoPhysicalAcceptanceError("C11 evidence must prove a read-only session with no write attempt")
    if virtualization is not False:
        raise CiscoPhysicalAcceptanceError("virtual evidence cannot satisfy the physical-evidence contract")

    schema_digest = _digest(schema_inventory_digest_sha256, "schema_inventory_digest_sha256")
    observation_digest = _digest(observation_digest_sha256, "observation_digest_sha256")
    target_digest = _digest(target_identity_digest_sha256, "target_identity_digest_sha256")
    attestation_digest = _digest(human_attestation_digest_sha256, "human_attestation_digest_sha256")

    sanitized = {
        "target_kind": kind,
        "model": model.strip(),
        "iosxe_version": iosxe_version.strip(),
        "platform_family": decision.family or "",
        "role": decision.role.value,
        "transport": transport_value,
        "source_sha": commit_sha,
        "schema_inventory_digest_sha256": schema_digest,
        "observation_digest_sha256": observation_digest,
        "target_identity_digest_sha256": target_digest,
        "human_attestation_digest_sha256": attestation_digest,
        "evidence_origin": evidence_origin,
        "read_only": True,
        "write_attempted": False,
        "virtualization": False,
        "catalog_digest_sha256": _canonical_sha256(catalog),
    }
    contract_digest = _canonical_sha256(sanitized)
    return PhysicalReadOnlyEvidenceClaim(
        target_kind=kind,
        model=model.strip(),
        iosxe_version=iosxe_version.strip(),
        platform_family=decision.family or "",
        role=decision.role.value,
        transport=transport_value,
        source_sha=commit_sha,
        schema_inventory_digest_sha256=schema_digest,
        observation_digest_sha256=observation_digest,
        target_identity_digest_sha256=target_digest,
        human_attestation_digest_sha256=attestation_digest,
        contract_digest_sha256=contract_digest,
    )
