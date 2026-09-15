from __future__ import annotations

from dataclasses import dataclass
from enum import Enum

from .backup import backup_operations


class MikroTikDeploymentStage(str, Enum):
    DISCOVER = "discover"
    NORMALIZE = "normalize"
    RESOLVE_INTENT = "resolve_intent"
    RETRIEVE_OFFLINE_KNOWLEDGE = "retrieve_offline_knowledge"
    OPTIONAL_AI_REASONING = "optional_ai_reasoning"
    PLAN = "plan"
    VALIDATE = "validate"
    PRE_CHANGE_BACKUP = "pre_change_backup"
    APPROVAL = "approval"
    APPLY = "apply"
    VERIFY = "verify"
    POST_CHANGE_BACKUP = "post_change_backup"
    GENERATE_HANDOVER = "generate_handover"
    COMPLETE = "complete"


@dataclass(frozen=True)
class MikroTikStageContract:
    stage: MikroTikDeploymentStage
    mutates_router: bool
    required_outputs: tuple[str, ...]
    notes: tuple[str, ...] = ()


def deployment_contract() -> tuple[MikroTikStageContract, ...]:
    return (
        MikroTikStageContract(MikroTikDeploymentStage.DISCOVER, False, ("raw RouterOS evidence",)),
        MikroTikStageContract(MikroTikDeploymentStage.NORMALIZE, False, ("normalized MikroTik state",)),
        MikroTikStageContract(MikroTikDeploymentStage.RESOLVE_INTENT, False, ("explicit operator intent", "missing-fact list")),
        MikroTikStageContract(MikroTikDeploymentStage.RETRIEVE_OFFLINE_KNOWLEDGE, False, ("knowledge citations/record IDs",), ("No Internet required at runtime.",)),
        MikroTikStageContract(MikroTikDeploymentStage.OPTIONAL_AI_REASONING, False, ("advisory reasoning or deterministic no-AI result",), ("AI never authorizes writes.",)),
        MikroTikStageContract(MikroTikDeploymentStage.PLAN, False, ("desired-state diff", "ordered RouterOS operations")),
        MikroTikStageContract(MikroTikDeploymentStage.VALIDATE, False, ("safety findings", "management survival proof", "rollback plan")),
        MikroTikStageContract(MikroTikDeploymentStage.PRE_CHANGE_BACKUP, True, tuple(item.kind.value for item in backup_operations(phase="pre_change"))),
        MikroTikStageContract(MikroTikDeploymentStage.APPROVAL, False, ("approval evidence",)),
        MikroTikStageContract(MikroTikDeploymentStage.APPLY, True, ("per-operation execution evidence",), ("Management-critical changes are applied in small verified batches.",)),
        MikroTikStageContract(MikroTikDeploymentStage.VERIFY, False, ("functional verification", "security verification", "idempotency verification")),
        MikroTikStageContract(MikroTikDeploymentStage.POST_CHANGE_BACKUP, True, tuple(item.kind.value for item in backup_operations(phase="post_change"))),
        MikroTikStageContract(MikroTikDeploymentStage.GENERATE_HANDOVER, False, ("completion report", "handover record", "as-built", "operations-maintenance guide", "backup manifest")),
        MikroTikStageContract(MikroTikDeploymentStage.COMPLETE, False, ("signed/hashed handover bundle manifest",)),
    )


def completion_requirements() -> tuple[str, ...]:
    return (
        "all configured intents verified",
        "post-change normalized state captured",
        "post-change sanitized export captured",
        "post-change encrypted binary backup captured",
        "backup hashes and RouterOS version recorded",
        "deployment completion report generated",
        "handover record generated",
        "as-built document generated",
        "operations and maintenance guide generated",
        "bundle manifest hashed",
    )
