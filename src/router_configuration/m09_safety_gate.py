from __future__ import annotations

from dataclasses import dataclass
from enum import Enum

from .m02_state_engine import ChangePlan
from .types import RiskLevel


class GateMode(str, Enum):
    READ_ONLY = "read_only"
    PLAN_ONLY = "plan_only"
    CHANGE = "change"


@dataclass(frozen=True)
class SafetyContext:
    production: bool = True
    backup_available: bool = False
    management_path_verified: bool = False
    explicit_authorization: bool = False
    critical_approval: bool = False


@dataclass(frozen=True)
class SafetyDecision:
    allowed: bool
    max_risk: RiskLevel
    reasons: tuple[str, ...]


class SafetyGate:
    """Authorizes whether an already-built plan may be applied.

    The gate does not mutate a device. It only evaluates execution preconditions.
    """

    def authorize_apply(
        self,
        plan: ChangePlan,
        *,
        mode: GateMode,
        context: SafetyContext,
    ) -> SafetyDecision:
        reasons: list[str] = []

        if plan.is_noop:
            return SafetyDecision(True, RiskLevel.READ_ONLY, ())

        if mode is not GateMode.CHANGE:
            reasons.append("gate mode does not permit writes")

        if not context.explicit_authorization:
            reasons.append("explicit authorization is required for writes")

        if context.production and not context.backup_available:
            reasons.append("production change requires a completed backup")

        if plan.max_risk >= RiskLevel.NETWORK_CHANGE and not context.management_path_verified:
            reasons.append(
                "network-path or security change requires verified management reachability"
            )

        if plan.max_risk >= RiskLevel.CRITICAL_CHANGE and not context.critical_approval:
            reasons.append("critical change requires separate critical approval")

        return SafetyDecision(
            allowed=not reasons,
            max_risk=plan.max_risk,
            reasons=tuple(reasons),
        )
