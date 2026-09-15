from __future__ import annotations

from dataclasses import dataclass

from .diagnostics import DiagnosticPlan, build_diagnostic_plan
from .playbooks import TroubleshootingPlaybook, get_playbook
from .privilege_profiles import PrivilegeProfile, PrivilegeProfileKind, build_privilege_profile
from .risk_policy import ToolRisk, classify_plan_risk
from .tool_registry import MikroTikTransport
from .transport_policy import select_transport


@dataclass(frozen=True)
class DiagnosticSession:
    playbook: TroubleshootingPlaybook
    plan: DiagnosticPlan
    privilege_profile: PrivilegeProfile
    risk: ToolRisk
    transports: tuple[tuple[str, MikroTikTransport], ...]

    def as_dict(self) -> dict[str, object]:
        return {
            "schema_version": "mikrotik-diagnostic-session/1",
            "playbook": self.playbook.name,
            "tool_names": [tool.name for tool in self.plan.tools],
            "privilege_profile": self.privilege_profile.kind.value,
            "risk": int(self.risk),
            "transports": {name: transport.value for name, transport in self.transports},
            "write_authorized": False,
        }


def build_diagnostic_session(playbook_name: str, *, include_capture: bool = False) -> DiagnosticSession:
    playbook = get_playbook(playbook_name)
    if include_capture and not playbook.capture_default:
        # Capture remains an explicit caller decision; the playbook never escalates itself.
        pass
    plan = build_diagnostic_plan(playbook.features, include_capture=include_capture)
    profile_kind = PrivilegeProfileKind.CAPTURE if include_capture else PrivilegeProfileKind.DIAGNOSTIC
    profile = build_privilege_profile(profile_kind, plan.tools)
    transports = tuple((tool.name, select_transport(tool)) for tool in plan.tools)
    return DiagnosticSession(
        playbook=playbook,
        plan=plan,
        privilege_profile=profile,
        risk=classify_plan_risk(plan.tools),
        transports=transports,
    )
