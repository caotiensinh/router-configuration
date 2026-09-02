from __future__ import annotations

import ipaddress
from dataclasses import dataclass
from enum import Enum
from typing import Any, Mapping

from .deployment_profile import DeploymentProfileValidator
from .routeros_capabilities import assess_routeros_capabilities


class FindingSeverity(str, Enum):
    BLOCKING = "blocking"
    WARNING = "warning"
    INFO = "info"


@dataclass(frozen=True)
class PreflightFinding:
    code: str
    severity: FindingSeverity
    message: str
    remediation: str

    def as_dict(self) -> dict[str, str]:
        return {
            "code": self.code,
            "severity": self.severity.value,
            "message": self.message,
            "remediation": self.remediation,
        }


@dataclass(frozen=True)
class PreflightResult:
    findings: tuple[PreflightFinding, ...]

    @property
    def ok(self) -> bool:
        return not any(
            finding.severity is FindingSeverity.BLOCKING
            for finding in self.findings
        )

    @property
    def blockers(self) -> tuple[PreflightFinding, ...]:
        return tuple(
            finding
            for finding in self.findings
            if finding.severity is FindingSeverity.BLOCKING
        )

    def as_dict(self) -> dict[str, Any]:
        return {
            "ok": self.ok,
            "blocking_count": len(self.blockers),
            "findings": [finding.as_dict() for finding in self.findings],
        }


class RouterOSPreflightEvaluator:
    """Compare a guided deployment profile with sanitized discovery evidence.

    This evaluator is read-only. It does not render or execute RouterOS commands.
    """

    def evaluate(
        self,
        profile: Mapping[str, Any],
        evidence: Mapping[str, Any],
    ) -> PreflightResult:
        findings: list[PreflightFinding] = []

        validation = DeploymentProfileValidator().validate(profile)
        for error in validation.errors:
            findings.append(
                PreflightFinding(
                    code="profile.invalid",
                    severity=FindingSeverity.BLOCKING,
                    message=error,
                    remediation="Fix the deployment profile and rerun routerctl profile-check before preflight.",
                )
            )
        for warning in validation.warnings:
            findings.append(
                PreflightFinding(
                    code="profile.warning",
                    severity=FindingSeverity.WARNING,
                    message=warning,
                    remediation="Document the missing production metadata before enabling write operations.",
                )
            )

        if evidence.get("schema_version") != "routeros-discovery-evidence/1":
            findings.append(
                PreflightFinding(
                    code="evidence.schema",
                    severity=FindingSeverity.BLOCKING,
                    message="unsupported or missing RouterOS discovery evidence schema",
                    remediation="Run routerctl routeros-discover with the current project version and use its sanitized evidence file.",
                )
            )
            return PreflightResult(tuple(findings))

        state = evidence.get("normalized_state")
        if not isinstance(state, Mapping):
            findings.append(
                PreflightFinding(
                    code="evidence.state_missing",
                    severity=FindingSeverity.BLOCKING,
                    message="discovery evidence does not contain normalized_state",
                    remediation="Repeat read-only discovery; do not proceed to rendering or apply.",
                )
            )
            return PreflightResult(tuple(findings))

        capability = assess_routeros_capabilities(state)
        for blocker in capability.blockers:
            findings.append(
                PreflightFinding(
                    code="capability.blocker",
                    severity=FindingSeverity.BLOCKING,
                    message=blocker,
                    remediation="Resolve RouterOS version or identity/resource discovery before continuing.",
                )
            )
        for warning in capability.warnings:
            findings.append(
                PreflightFinding(
                    code="capability.gap",
                    severity=FindingSeverity.WARNING,
                    message=warning,
                    remediation="Confirm whether the missing feature is required by the deployment intent; restore discovery coverage if it is required.",
                )
            )

        device = profile.get("device", {})
        if isinstance(device, Mapping):
            vendor = str(device.get("vendor", "")).lower()
            if vendor and vendor != "mikrotik":
                findings.append(
                    PreflightFinding(
                        code="device.vendor_mismatch",
                        severity=FindingSeverity.BLOCKING,
                        message=f"RouterOS preflight cannot validate vendor {vendor!r}",
                        remediation="Use the vendor-specific adapter/preflight path that matches the deployment profile.",
                    )
                )

            expected_model = str(device.get("model", "")).strip()
            discovered_model = str(state.get("platform", {}).get("board_name") or "").strip()
            if expected_model and discovered_model and expected_model != discovered_model:
                findings.append(
                    PreflightFinding(
                        code="device.model_mismatch",
                        severity=FindingSeverity.BLOCKING,
                        message=f"profile expects {expected_model} but discovery reports {discovered_model}",
                        remediation="Confirm the management IP and router identity before any configuration change.",
                    )
                )

        interfaces = self._interfaces_by_name(state)
        topology = profile.get("topology", {})
        if isinstance(topology, Mapping):
            for wan in topology.get("wans", []):
                if not isinstance(wan, Mapping) or not bool(wan.get("enabled", True)):
                    continue
                name = str(wan.get("interface", "")).strip()
                if name:
                    self._check_interface(
                        findings,
                        interfaces,
                        name,
                        role=f"WAN {wan.get('name', name)}",
                    )

            core = topology.get("core")
            if isinstance(core, Mapping):
                name = str(core.get("interface", "")).strip()
                if name:
                    self._check_interface(findings, interfaces, name, role="core uplink")

        intent = profile.get("intent", {})
        if isinstance(intent, Mapping):
            capabilities = dict(capability.capabilities)

            if isinstance(intent.get("multiwan"), Mapping) and not capabilities.get("routing", False):
                findings.append(
                    self._feature_blocker(
                        "routing.required",
                        "Multi-WAN intent requires complete route/routing-table discovery.",
                        "Restore routing discovery before generating Dual-WAN or policy-routing changes.",
                    )
                )

            if isinstance(intent.get("security"), Mapping) and not capabilities.get("firewall", False):
                findings.append(
                    self._feature_blocker(
                        "firewall.required",
                        "security intent requires complete firewall/NAT discovery.",
                        "Restore firewall filter and NAT discovery before security changes.",
                    )
                )

            vpn = intent.get("vpn")
            if (
                isinstance(vpn, Mapping)
                and isinstance(vpn.get("wireguard"), Mapping)
                and bool(vpn["wireguard"].get("enabled", False))
                and not capabilities.get("wireguard", False)
            ):
                findings.append(
                    self._feature_blocker(
                        "wireguard.required",
                        "WireGuard is requested but WireGuard discovery is incomplete.",
                        "Restore WireGuard interface/peer discovery or disable the WireGuard intent.",
                    )
                )

            qos = intent.get("qos")
            if (
                isinstance(qos, Mapping)
                and bool(qos.get("enabled", False))
                and not capabilities.get("qos", False)
            ):
                findings.append(
                    self._feature_blocker(
                        "qos.required",
                        "QoS is requested but queue discovery is incomplete.",
                        "Restore simple-queue and queue-tree discovery or disable QoS intent.",
                    )
                )

        self._check_management_address(profile, state, findings)

        if not findings:
            findings.append(
                PreflightFinding(
                    code="preflight.ready",
                    severity=FindingSeverity.INFO,
                    message="profile and discovery evidence are compatible for the current read-only preflight scope",
                    remediation="Continue to plan/renderer validation only; this result does not authorize writes.",
                )
            )

        findings.sort(key=lambda finding: (self._severity_rank(finding.severity), finding.code, finding.message))
        return PreflightResult(tuple(findings))

    @staticmethod
    def _severity_rank(severity: FindingSeverity) -> int:
        return {
            FindingSeverity.BLOCKING: 0,
            FindingSeverity.WARNING: 1,
            FindingSeverity.INFO: 2,
        }[severity]

    @staticmethod
    def _interfaces_by_name(state: Mapping[str, Any]) -> dict[str, Mapping[str, Any]]:
        result: dict[str, Mapping[str, Any]] = {}
        interfaces = state.get("interfaces", [])
        if isinstance(interfaces, list):
            for item in interfaces:
                if isinstance(item, Mapping):
                    name = str(item.get("name", "")).strip()
                    if name:
                        result[name] = item
        return result

    @staticmethod
    def _check_interface(
        findings: list[PreflightFinding],
        interfaces: Mapping[str, Mapping[str, Any]],
        name: str,
        *,
        role: str,
    ) -> None:
        interface = interfaces.get(name)
        if interface is None:
            findings.append(
                PreflightFinding(
                    code="interface.missing",
                    severity=FindingSeverity.BLOCKING,
                    message=f"{role} interface {name!r} is not present in discovery state",
                    remediation="Verify the selected physical port name and rerun read-only discovery.",
                )
            )
            return

        if interface.get("disabled") is True:
            findings.append(
                PreflightFinding(
                    code="interface.disabled",
                    severity=FindingSeverity.BLOCKING,
                    message=f"{role} interface {name!r} is disabled",
                    remediation="Confirm cabling/port intent with an administrator before planning any enable operation.",
                )
            )
        elif interface.get("running") is False:
            findings.append(
                PreflightFinding(
                    code="interface.link_down",
                    severity=FindingSeverity.WARNING,
                    message=f"{role} interface {name!r} is not running",
                    remediation="Check cable/SFP/ONU/switch link state before deployment; do not assume a configuration fault.",
                )
            )

    @staticmethod
    def _feature_blocker(code: str, message: str, remediation: str) -> PreflightFinding:
        return PreflightFinding(
            code=code,
            severity=FindingSeverity.BLOCKING,
            message=message,
            remediation=remediation,
        )

    @staticmethod
    def _check_management_address(
        profile: Mapping[str, Any],
        state: Mapping[str, Any],
        findings: list[PreflightFinding],
    ) -> None:
        device = profile.get("device", {})
        if not isinstance(device, Mapping):
            return
        target = str(device.get("management_target", "")).strip()
        try:
            management_ip = ipaddress.ip_address(target)
        except ValueError:
            return

        discovered: set[str] = set()
        addresses = state.get("ip_addresses", [])
        if isinstance(addresses, list):
            for item in addresses:
                if not isinstance(item, Mapping):
                    continue
                value = str(item.get("address", "")).strip()
                if not value:
                    continue
                try:
                    discovered.add(str(ipaddress.ip_interface(value).ip))
                except ValueError:
                    continue

        if discovered and str(management_ip) not in discovered:
            findings.append(
                PreflightFinding(
                    code="management.address_unconfirmed",
                    severity=FindingSeverity.WARNING,
                    message=f"management target {management_ip} is not present in discovered IP addresses",
                    remediation="Confirm NAT/VRF/management routing or the selected device identity before enabling writes.",
                )
            )
