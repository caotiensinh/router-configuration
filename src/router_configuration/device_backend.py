from __future__ import annotations

from dataclasses import dataclass
from enum import IntEnum
from typing import Any, Mapping, Protocol, runtime_checkable


class BackendContractError(ValueError):
    pass


class EvidenceClass(IntEnum):
    VENDOR_DOCUMENT_VERIFIED = 1
    VIRTUAL_VERIFIED = 2
    PROTOCOL_VERIFIED = 3
    HARDWARE_VERIFIED = 4


@dataclass(frozen=True)
class BackendIdentity:
    backend_kind: str
    vendor: str
    model: str
    hardware_version: str | None = None
    firmware_version: str | None = None
    controller_version: str | None = None
    hardware_present: bool = False

    def __post_init__(self) -> None:
        if not self.backend_kind.strip() or not self.vendor.strip() or not self.model.strip():
            raise BackendContractError("backend_kind, vendor, and model are required")


@dataclass(frozen=True)
class BackendCapabilities:
    discover: bool = True
    snapshot: bool = True
    plan: bool = True
    read_back: bool = True
    verify: bool = True
    apply: bool = False
    rollback: bool = False
    write_authorized: bool = False

    def __post_init__(self) -> None:
        if self.write_authorized and not self.apply:
            raise BackendContractError("write_authorized requires apply capability")


@runtime_checkable
class DeviceBackend(Protocol):
    @property
    def identity(self) -> BackendIdentity: ...

    @property
    def capabilities(self) -> BackendCapabilities: ...

    @property
    def evidence_ceiling(self) -> EvidenceClass: ...

    def discover(self) -> Mapping[str, Any]: ...

    def snapshot(self) -> Mapping[str, Any]: ...

    def plan(self, desired_state: Mapping[str, Any]) -> Mapping[str, Any]: ...

    def read_back(self) -> Mapping[str, Any]: ...

    def verify(self, desired_state: Mapping[str, Any], observed_state: Mapping[str, Any]) -> Mapping[str, Any]: ...


@runtime_checkable
class MutatingDeviceBackend(DeviceBackend, Protocol):
    def apply(self, plan: Mapping[str, Any]) -> Mapping[str, Any]: ...

    def rollback(self, checkpoint: Mapping[str, Any]) -> Mapping[str, Any]: ...


def expected_evidence_ceiling(identity: BackendIdentity) -> EvidenceClass:
    kind = identity.backend_kind.strip()
    if kind == "VirtualBackend":
        return EvidenceClass.VIRTUAL_VERIFIED
    if kind in {"SSHBackend", "HTTPAPIBackend", "ControllerBackend"}:
        return EvidenceClass.PROTOCOL_VERIFIED
    if kind == "PhysicalDeviceBackend":
        if not identity.hardware_present:
            raise BackendContractError("PhysicalDeviceBackend requires hardware_present=true")
        return EvidenceClass.HARDWARE_VERIFIED
    raise BackendContractError("unknown backend kind fails closed")


def validate_backend_contract(backend: DeviceBackend) -> None:
    if not isinstance(backend, DeviceBackend):
        raise BackendContractError("backend does not implement DeviceBackend protocol")
    identity = backend.identity
    capabilities = backend.capabilities
    expected = expected_evidence_ceiling(identity)
    if backend.evidence_ceiling != expected:
        raise BackendContractError("backend evidence ceiling does not match backend kind")
    if capabilities.write_authorized and not isinstance(backend, MutatingDeviceBackend):
        raise BackendContractError("write-authorized backend must implement apply and rollback")


def assert_evidence_claim_allowed(backend: DeviceBackend, claim: EvidenceClass) -> None:
    validate_backend_contract(backend)
    if claim > backend.evidence_ceiling:
        raise BackendContractError("requested evidence claim exceeds backend evidence ceiling")
    if claim is EvidenceClass.HARDWARE_VERIFIED and not backend.identity.hardware_present:
        raise BackendContractError("hardware verification requires physical hardware")
