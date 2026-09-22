from __future__ import annotations

import hashlib
import hmac
import json
import re
from dataclasses import dataclass
from typing import Any, Mapping, Sequence

from .device_backend import EvidenceClass


NETWORK_SANDBOX_REPOSITORY = "caotiensinh/Network_Sandbox_Runtime"
NETWORK_SANDBOX_ACCEPTANCE_SCHEMA = "network-sandbox-cross-repo-acceptance/1"

_SHA40 = re.compile(r"^[0-9a-f]{40}$")
_SHA256 = re.compile(r"^[0-9a-f]{64}$")
_ALLOWED_FIDELITY = frozenset({"L1", "L2", "L3"})
_FORBIDDEN_CLAIM_PARTS = (
    "hardware_verified",
    "hardware-verified",
    "physical_verified",
    "physical-verified",
    "production_write",
    "production-write",
    "production_authorized",
    "production-authorized",
)


class NetworkSandboxAcceptanceError(ValueError):
    """Raised when cross-repository sandbox evidence violates the acceptance boundary."""


def _canonical_sha256(value: Any) -> str:
    encoded = json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        default=str,
    ).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def _sha40(value: object, label: str) -> str:
    text = str(value or "").strip().lower()
    if not _SHA40.fullmatch(text):
        raise NetworkSandboxAcceptanceError(f"{label} must be a lowercase 40-character git SHA")
    return text


def _sha256(value: object, label: str) -> str:
    text = str(value or "").strip().lower()
    if not _SHA256.fullmatch(text):
        raise NetworkSandboxAcceptanceError(f"{label} must be a lowercase SHA-256 digest")
    return text


def _single_line(value: object, label: str) -> str:
    text = str(value or "").strip()
    if not text or any(character in text for character in ("\n", "\r", "\x00")):
        raise NetworkSandboxAcceptanceError(f"{label} must be a non-empty single-line value")
    return text


def _strings(values: Sequence[object], label: str) -> tuple[str, ...]:
    if isinstance(values, (str, bytes, bytearray)):
        raise NetworkSandboxAcceptanceError(f"{label} must be an array")
    normalized = tuple(_single_line(item, f"{label}[]") for item in values)
    if not normalized:
        raise NetworkSandboxAcceptanceError(f"{label} must not be empty")
    return normalized


def _evidence_class_for_fidelity(fidelity_level: str) -> EvidenceClass:
    if fidelity_level in {"L1", "L2"}:
        return EvidenceClass.VIRTUAL_VERIFIED
    if fidelity_level == "L3":
        return EvidenceClass.PROTOCOL_VERIFIED
    raise NetworkSandboxAcceptanceError(
        "only L1-L3 sandbox evidence is admitted by the hardware-free acceptance contract"
    )


def _reject_hardware_or_production_claims(claims: Sequence[str]) -> None:
    for claim in claims:
        normalized = claim.strip().lower()
        if any(part in normalized for part in _FORBIDDEN_CLAIM_PARTS):
            raise NetworkSandboxAcceptanceError(
                f"sandbox evidence cannot satisfy hardware/production claim: {claim}"
            )


@dataclass(frozen=True)
class NetworkSandboxAcceptance:
    payload: Mapping[str, Any]

    def as_dict(self) -> dict[str, Any]:
        return dict(self.payload)


def build_network_sandbox_acceptance(
    *,
    router_configuration_sha: str,
    network_sandbox_sha: str,
    network_sandbox_release: str,
    fidelity_level: str,
    scenario_id: str,
    scenario_sha256: str,
    result_sha256: str,
    tested_logic: Sequence[str],
    evidence_refs: Sequence[str],
    eligible_claims: Sequence[str],
) -> NetworkSandboxAcceptance:
    """Build hash-bound simulation/protocol evidence without hardware promotion.

    This contract deliberately admits Network_Sandbox_Runtime L1-L3 evidence only.
    Licensed vendor-golden L4 and physical hardware acceptance remain separate gates.
    """

    router_sha = _sha40(router_configuration_sha, "router_configuration_sha")
    sandbox_sha = _sha40(network_sandbox_sha, "network_sandbox_sha")
    release = _single_line(network_sandbox_release, "network_sandbox_release")
    fidelity = _single_line(fidelity_level, "fidelity_level").upper()
    if fidelity not in _ALLOWED_FIDELITY:
        raise NetworkSandboxAcceptanceError(
            f"unsupported hardware-free sandbox fidelity level: {fidelity}"
        )
    scenario = _single_line(scenario_id, "scenario_id")
    scenario_digest = _sha256(scenario_sha256, "scenario_sha256")
    result_digest = _sha256(result_sha256, "result_sha256")
    logic = _strings(tested_logic, "tested_logic")
    refs = _strings(evidence_refs, "evidence_refs")
    claims = _strings(eligible_claims, "eligible_claims")
    _reject_hardware_or_production_claims(claims)

    evidence_class = _evidence_class_for_fidelity(fidelity)
    payload: dict[str, Any] = {
        "schema_version": NETWORK_SANDBOX_ACCEPTANCE_SCHEMA,
        "source_repository": NETWORK_SANDBOX_REPOSITORY,
        "router_configuration_sha": router_sha,
        "network_sandbox_sha": sandbox_sha,
        "network_sandbox_release": release,
        "fidelity_level": fidelity,
        "evidence_class": evidence_class.name,
        "scenario_id": scenario,
        "scenario_sha256": scenario_digest,
        "result_sha256": result_digest,
        "tested_logic": sorted(set(logic)),
        "evidence_refs": sorted(set(refs)),
        "eligible_claims": sorted(set(claims)),
        "hardware_present": False,
        "hardware_verified": False,
        "physical_device_verified": False,
        "production_write_authorized": False,
        "production_writer_available": False,
        "claim": "hardware_free_acceptance_only",
    }
    payload["acceptance_sha256"] = _canonical_sha256(payload)
    return NetworkSandboxAcceptance(payload)


def validate_network_sandbox_acceptance(record: Mapping[str, Any]) -> EvidenceClass:
    if record.get("schema_version") != NETWORK_SANDBOX_ACCEPTANCE_SCHEMA:
        raise NetworkSandboxAcceptanceError("unsupported network sandbox acceptance schema")
    if record.get("source_repository") != NETWORK_SANDBOX_REPOSITORY:
        raise NetworkSandboxAcceptanceError("unexpected network sandbox source repository")

    _sha40(record.get("router_configuration_sha"), "router_configuration_sha")
    _sha40(record.get("network_sandbox_sha"), "network_sandbox_sha")
    _single_line(record.get("network_sandbox_release"), "network_sandbox_release")

    fidelity = _single_line(record.get("fidelity_level"), "fidelity_level").upper()
    if fidelity not in _ALLOWED_FIDELITY:
        raise NetworkSandboxAcceptanceError("unsupported sandbox fidelity level")
    expected_class = _evidence_class_for_fidelity(fidelity)
    if record.get("evidence_class") != expected_class.name:
        raise NetworkSandboxAcceptanceError("sandbox evidence class exceeds fidelity ceiling")

    _single_line(record.get("scenario_id"), "scenario_id")
    _sha256(record.get("scenario_sha256"), "scenario_sha256")
    _sha256(record.get("result_sha256"), "result_sha256")

    logic = record.get("tested_logic")
    refs = record.get("evidence_refs")
    claims = record.get("eligible_claims")
    if not isinstance(logic, list) or not logic:
        raise NetworkSandboxAcceptanceError("tested_logic must be a non-empty array")
    if not isinstance(refs, list) or not refs:
        raise NetworkSandboxAcceptanceError("evidence_refs must be a non-empty array")
    if not isinstance(claims, list) or not claims:
        raise NetworkSandboxAcceptanceError("eligible_claims must be a non-empty array")
    _reject_hardware_or_production_claims([str(item) for item in claims])

    for field in (
        "hardware_present",
        "hardware_verified",
        "physical_device_verified",
        "production_write_authorized",
        "production_writer_available",
    ):
        if record.get(field) is not False:
            raise NetworkSandboxAcceptanceError(
                f"hardware-free sandbox acceptance must keep {field}=false"
            )
    if record.get("claim") != "hardware_free_acceptance_only":
        raise NetworkSandboxAcceptanceError("sandbox acceptance claim boundary changed")

    supplied = _sha256(record.get("acceptance_sha256"), "acceptance_sha256")
    unsigned = dict(record)
    unsigned.pop("acceptance_sha256", None)
    expected = _canonical_sha256(unsigned)
    if not hmac.compare_digest(supplied, expected):
        raise NetworkSandboxAcceptanceError("network sandbox acceptance digest mismatch")

    return expected_class
