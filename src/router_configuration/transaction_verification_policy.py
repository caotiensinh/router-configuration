from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from typing import Any, Iterable


class VerificationCheck(str, Enum):
    MANAGEMENT = "management"
    INTENDED_STATE = "intended_state"
    WAN = "wan"
    DNS = "dns"
    ROUTING = "routing"
    VPN = "vpn"


@dataclass(frozen=True)
class TransactionVerificationPolicy:
    features: tuple[str, ...]
    required_checks: tuple[VerificationCheck, ...]

    def as_dict(self) -> dict[str, Any]:
        return {
            "schema_version": "routeros-transaction-verification-policy/1",
            "features": list(self.features),
            "required_checks": [item.value for item in self.required_checks],
            "management_required": VerificationCheck.MANAGEMENT in self.required_checks,
            "transport_present": False,
            "production_writer_available": False,
            "write_authorized": False,
        }


_FEATURE_CHECKS = {
    "topology": {VerificationCheck.WAN, VerificationCheck.ROUTING},
    "multiwan": {VerificationCheck.WAN, VerificationCheck.ROUTING},
    "routing": {VerificationCheck.WAN, VerificationCheck.ROUTING},
    "firewall": {VerificationCheck.MANAGEMENT},
    "security": {VerificationCheck.MANAGEMENT},
    "management": {VerificationCheck.MANAGEMENT},
    "dns": {VerificationCheck.DNS},
    "vpn": {VerificationCheck.VPN, VerificationCheck.ROUTING},
    "wireguard": {VerificationCheck.VPN, VerificationCheck.ROUTING},
    "vlan": {VerificationCheck.MANAGEMENT},
    "qos": set(),
}


def derive_transaction_verification_policy(
    features: Iterable[str],
) -> TransactionVerificationPolicy:
    normalized = tuple(sorted({str(item).strip().lower() for item in features if str(item).strip()}))
    if not normalized:
        raise ValueError("at least one changed feature is required")

    checks = {VerificationCheck.MANAGEMENT, VerificationCheck.INTENDED_STATE}
    unknown: list[str] = []
    for feature in normalized:
        mapped = _FEATURE_CHECKS.get(feature)
        if mapped is None:
            unknown.append(feature)
            continue
        checks.update(mapped)
    if unknown:
        raise ValueError("verification policy has no accepted mapping for: " + ", ".join(unknown))

    ordered = tuple(sorted(checks, key=lambda item: item.value))
    return TransactionVerificationPolicy(features=normalized, required_checks=ordered)
