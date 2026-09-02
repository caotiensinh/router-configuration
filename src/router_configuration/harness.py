from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Iterable


class Environment(str, Enum):
    LAB = "lab"
    STAGING = "staging"
    PRODUCTION = "production"


class OperatorMode(str, Enum):
    GUIDED = "guided"
    ADMIN = "admin"
    EXPERT = "expert"


class ExecutionStage(str, Enum):
    CREATED = "created"
    DISCOVER = "discover"
    INSPECT = "inspect"
    PLAN = "plan"
    VALIDATE = "validate"
    BACKUP = "backup"
    PREFLIGHT = "preflight"
    APPROVAL = "approval"
    APPLY = "apply"
    VERIFY = "verify"
    SAVE = "save"
    COMPLETE = "complete"
    ROLLBACK = "rollback"
    BLOCKED = "blocked"


class EvidenceKind(str, Enum):
    DEVICE_FACTS = "device_facts"
    ACTUAL_STATE = "actual_state"
    PLAN = "plan"
    VALIDATION = "validation"
    BACKUP = "backup"
    CAPABILITY_CHECK = "capability_check"
    MANAGEMENT_PATH = "management_path"
    CONNECTIVITY_BASELINE = "connectivity_baseline"
    APPROVAL = "approval"
    APPLY_RESULT = "apply_result"
    VERIFY_RESULT = "verify_result"
    SAVE_RESULT = "save_result"
    ROLLBACK_RESULT = "rollback_result"


@dataclass(frozen=True)
class DeploymentSpec:
    device_id: str
    vendor: str
    management_target: str
    environment: Environment = Environment.PRODUCTION
    operator_mode: OperatorMode = OperatorMode.GUIDED
    site_name: str = "default"
    allow_write: bool = False

    def validate(self) -> tuple[str, ...]:
        reasons: list[str] = []
        if not self.device_id.strip():
            reasons.append("device_id is required")
        if not self.vendor.strip():
            reasons.append("vendor is required")
        if not self.management_target.strip():
            reasons.append("management_target is required")
        if not self.site_name.strip():
            reasons.append("site_name is required")
        return tuple(reasons)


@dataclass(frozen=True)
class EvidenceRecord:
    kind: EvidenceKind
    ok: bool
    summary: str
    artifact_ref: str | None = None


@dataclass(frozen=True)
class GuidedStep:
    stage: ExecutionStage
    title: str
    purpose: str
    success_criteria: str
    failure_action: str


@dataclass(frozen=True)
class TransitionDecision:
    allowed: bool
    current_stage: ExecutionStage
    next_stage: ExecutionStage
    reasons: tuple[str, ...] = ()
    required_evidence: tuple[EvidenceKind, ...] = ()


@dataclass
class HarnessRun:
    spec: DeploymentSpec
    stage: ExecutionStage = ExecutionStage.CREATED
    evidence: list[EvidenceRecord] = field(default_factory=list)
    history: list[ExecutionStage] = field(default_factory=lambda: [ExecutionStage.CREATED])

    def record(self, record: EvidenceRecord) -> None:
        self.evidence.append(record)

    def latest(self, kind: EvidenceKind) -> EvidenceRecord | None:
        for item in reversed(self.evidence):
            if item.kind is kind:
                return item
        return None


class HarnessEngine:
    """Deterministic deployment harness.

    It coordinates evidence and stage transitions only. It never talks to a router
    directly and therefore cannot bypass vendor adapters or the safety gate.
    """

    _NORMAL_SEQUENCE = (
        ExecutionStage.CREATED,
        ExecutionStage.DISCOVER,
        ExecutionStage.INSPECT,
        ExecutionStage.PLAN,
        ExecutionStage.VALIDATE,
        ExecutionStage.BACKUP,
        ExecutionStage.PREFLIGHT,
        ExecutionStage.APPROVAL,
        ExecutionStage.APPLY,
        ExecutionStage.VERIFY,
        ExecutionStage.SAVE,
        ExecutionStage.COMPLETE,
    )

    _ENTER_REQUIREMENTS = {
        ExecutionStage.INSPECT: (EvidenceKind.DEVICE_FACTS,),
        ExecutionStage.PLAN: (EvidenceKind.ACTUAL_STATE,),
        ExecutionStage.VALIDATE: (EvidenceKind.PLAN,),
        ExecutionStage.BACKUP: (EvidenceKind.VALIDATION,),
        ExecutionStage.PREFLIGHT: (EvidenceKind.BACKUP,),
        ExecutionStage.APPROVAL: (
            EvidenceKind.CAPABILITY_CHECK,
            EvidenceKind.MANAGEMENT_PATH,
            EvidenceKind.CONNECTIVITY_BASELINE,
        ),
        ExecutionStage.APPLY: (EvidenceKind.APPROVAL,),
        ExecutionStage.VERIFY: (EvidenceKind.APPLY_RESULT,),
        ExecutionStage.SAVE: (EvidenceKind.VERIFY_RESULT,),
        ExecutionStage.COMPLETE: (EvidenceKind.SAVE_RESULT,),
    }

    def guide(self, stage: ExecutionStage) -> GuidedStep:
        guides = {
            ExecutionStage.DISCOVER: GuidedStep(stage, "Discover device", "Identify model, firmware and capabilities.", "Device identity and capabilities are collected without changing configuration.", "Stop and verify management address, credentials and physical topology."),
            ExecutionStage.INSPECT: GuidedStep(stage, "Inspect current state", "Read the running network state before planning.", "Interfaces, addresses, routes, firewall, VPN and QoS state are captured.", "Do not continue until read-only collection is complete and consistent."),
            ExecutionStage.PLAN: GuidedStep(stage, "Build change plan", "Compare desired intent with actual state.", "A deterministic diff lists every proposed change and risk level.", "Fix intent or discovery data; never compensate with ad-hoc CLI commands."),
            ExecutionStage.VALIDATE: GuidedStep(stage, "Validate plan", "Reject invalid or unsafe combinations before touching the router.", "Schema, capability, routing, security and management invariants pass.", "Correct the plan and rerun validation."),
            ExecutionStage.BACKUP: GuidedStep(stage, "Create recovery point", "Guarantee a recoverable pre-change configuration.", "Backup artifact is created, identified and readable.", "Block production changes until backup succeeds."),
            ExecutionStage.PREFLIGHT: GuidedStep(stage, "Run preflight", "Prove the router can be changed without losing control.", "Capabilities, management path and connectivity baseline all pass.", "Stop and resolve the failed prerequisite; do not override by default."),
            ExecutionStage.APPROVAL: GuidedStep(stage, "Approve bounded change", "Make the intended mutation explicit and auditable.", "An approval record exists for the exact plan being applied.", "Return to PLAN if the requested change or risk changed."),
            ExecutionStage.APPLY: GuidedStep(stage, "Apply approved plan", "Execute only operations present in the approved plan.", "Adapter reports bounded execution evidence for each operation.", "If mutation may have occurred, enter rollback handling."),
            ExecutionStage.VERIFY: GuidedStep(stage, "Verify service", "Prove routing, security, VPN and management still work.", "Post-change checks pass against the pre-change baseline and intended state.", "Automatically route to rollback when verification fails."),
            ExecutionStage.SAVE: GuidedStep(stage, "Persist configuration", "Persist only a verified configuration.", "The device reports successful save/persist and the state can be reread.", "Do not mark the run complete until persistence is confirmed."),
            ExecutionStage.ROLLBACK: GuidedStep(stage, "Rollback", "Restore the last known-good state after unsafe execution.", "Management and service verification pass after recovery.", "Escalate to controlled manual recovery; preserve all evidence."),
        }
        return guides.get(stage, GuidedStep(stage, stage.value.title(), "State marker.", "No pending action.", "Review run history."))

    def _next_normal_stage(self, current: ExecutionStage) -> ExecutionStage:
        idx = self._NORMAL_SEQUENCE.index(current)
        return self._NORMAL_SEQUENCE[min(idx + 1, len(self._NORMAL_SEQUENCE) - 1)]

    def _requirements_for(self, stage: ExecutionStage, spec: DeploymentSpec) -> tuple[EvidenceKind, ...]:
        requirements = list(self._ENTER_REQUIREMENTS.get(stage, ()))
        if stage is ExecutionStage.PREFLIGHT and spec.environment is not Environment.PRODUCTION:
            requirements = [item for item in requirements if item is not EvidenceKind.BACKUP]
        return tuple(requirements)

    def _missing_or_failed(self, run: HarnessRun, required: Iterable[EvidenceKind]) -> tuple[str, ...]:
        reasons: list[str] = []
        for kind in required:
            record = run.latest(kind)
            if record is None:
                reasons.append(f"missing evidence: {kind.value}")
            elif not record.ok:
                reasons.append(f"failed evidence: {kind.value}: {record.summary}")
        return tuple(reasons)

    def evaluate_advance(self, run: HarnessRun) -> TransitionDecision:
        spec_errors = run.spec.validate()
        if spec_errors:
            return TransitionDecision(False, run.stage, ExecutionStage.BLOCKED, spec_errors)

        if run.stage in (ExecutionStage.COMPLETE, ExecutionStage.BLOCKED):
            return TransitionDecision(False, run.stage, run.stage, ("run cannot advance from terminal stage",))

        if run.stage is ExecutionStage.ROLLBACK:
            required = (EvidenceKind.ROLLBACK_RESULT,)
            reasons = self._missing_or_failed(run, required)
            return TransitionDecision(not reasons, run.stage, ExecutionStage.COMPLETE, reasons, required)

        apply_result = run.latest(EvidenceKind.APPLY_RESULT)
        verify_result = run.latest(EvidenceKind.VERIFY_RESULT)
        if run.stage is ExecutionStage.APPLY and apply_result is not None and not apply_result.ok:
            return TransitionDecision(True, run.stage, ExecutionStage.ROLLBACK)
        if run.stage is ExecutionStage.VERIFY and verify_result is not None and not verify_result.ok:
            return TransitionDecision(True, run.stage, ExecutionStage.ROLLBACK)

        target = self._next_normal_stage(run.stage)
        required = self._requirements_for(target, run.spec)
        reasons = list(self._missing_or_failed(run, required))
        if target is ExecutionStage.APPLY and not run.spec.allow_write:
            reasons.append("writes are disabled by deployment spec")

        return TransitionDecision(not reasons, run.stage, target, tuple(reasons), required)

    def advance(self, run: HarnessRun) -> TransitionDecision:
        decision = self.evaluate_advance(run)
        if decision.allowed:
            run.stage = decision.next_stage
            run.history.append(decision.next_stage)
        return decision
