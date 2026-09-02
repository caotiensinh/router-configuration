from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from ipaddress import ip_network
from typing import Iterable


class FindingSeverity(str, Enum):
    INFO = "info"
    WARNING = "warning"
    ERROR = "error"


@dataclass(frozen=True)
class SecurityFinding:
    code: str
    severity: FindingSeverity
    message: str


@dataclass(frozen=True)
class SecurityBaseline:
    management_sources: tuple[str, ...]
    default_wan_input_deny: bool = True
    default_interzone_deny: bool = True
    anti_spoofing: bool = True
    bogon_filtering: bool = True
    log_denied_management: bool = True


class SecurityPolicyValidator:
    """Validates security intent without generating vendor commands."""

    def validate(self, baseline: SecurityBaseline) -> tuple[SecurityFinding, ...]:
        findings: list[SecurityFinding] = []

        if not baseline.default_wan_input_deny:
            findings.append(
                SecurityFinding(
                    "SEC-WAN-DEFAULT",
                    FindingSeverity.ERROR,
                    "WAN input policy should default to deny",
                )
            )

        if not baseline.management_sources:
            findings.append(
                SecurityFinding(
                    "SEC-MGMT-NONE",
                    FindingSeverity.ERROR,
                    "at least one bounded management source is required",
                )
            )

        for source in baseline.management_sources:
            try:
                network = ip_network(source, strict=False)
            except ValueError:
                findings.append(
                    SecurityFinding(
                        "SEC-MGMT-CIDR",
                        FindingSeverity.ERROR,
                        f"invalid management source CIDR: {source}",
                    )
                )
                continue

            if network.prefixlen == 0:
                findings.append(
                    SecurityFinding(
                        "SEC-MGMT-ANY",
                        FindingSeverity.ERROR,
                        "management access must not allow the entire address space",
                    )
                )

        if not baseline.anti_spoofing:
            findings.append(
                SecurityFinding(
                    "SEC-ANTISPOOF",
                    FindingSeverity.WARNING,
                    "anti-spoofing policy is disabled",
                )
            )

        if not baseline.bogon_filtering:
            findings.append(
                SecurityFinding(
                    "SEC-BOGON",
                    FindingSeverity.WARNING,
                    "bogon filtering is disabled",
                )
            )

        return tuple(findings)

    def has_blocking_findings(self, findings: Iterable[SecurityFinding]) -> bool:
        return any(item.severity is FindingSeverity.ERROR for item in findings)
