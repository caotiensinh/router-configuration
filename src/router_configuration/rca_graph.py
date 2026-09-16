from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from typing import Iterable


class EvidenceState(str, Enum):
    CONFIRMED = "CONFIRMED"
    REJECTED = "REJECTED"
    UNKNOWN = "UNKNOWN"


class EdgeKind(str, Enum):
    REQUIRES = "REQUIRES"
    SUPPORTS = "SUPPORTS"
    CONTRADICTS = "CONTRADICTS"


@dataclass(frozen=True)
class Evidence:
    evidence_id: str
    state: EvidenceState
    source: str
    observed_value: str | None = None


@dataclass(frozen=True)
class Hypothesis:
    hypothesis_id: str
    required_evidence: tuple[str, ...] = ()
    supporting_evidence: tuple[str, ...] = ()
    contradicting_evidence: tuple[str, ...] = ()


@dataclass(frozen=True)
class Assessment:
    hypothesis_id: str
    state: EvidenceState
    missing: tuple[str, ...]
    contradictions: tuple[str, ...]


@dataclass(frozen=True)
class DiagnosticCheck:
    evidence_id: str
    cost: int = 1
    read_only: bool = True


@dataclass(frozen=True)
class MinimumCheckPlan:
    checks: tuple[DiagnosticCheck, ...]
    blocked_evidence: tuple[str, ...]

    @property
    def executable(self) -> bool:
        return not self.blocked_evidence


class EvidenceRCAGraph:
    """Deterministic, fail-closed RCA evaluator and minimum-check planner."""

    def __init__(self, evidence: Iterable[Evidence] = ()) -> None:
        self._evidence = {item.evidence_id: item for item in evidence}

    def assess(self, hypothesis: Hypothesis) -> Assessment:
        contradictions = tuple(
            evidence_id
            for evidence_id in hypothesis.contradicting_evidence
            if self._state(evidence_id) is EvidenceState.CONFIRMED
        )
        if contradictions:
            return Assessment(hypothesis.hypothesis_id, EvidenceState.REJECTED, (), contradictions)

        missing = tuple(
            evidence_id
            for evidence_id in hypothesis.required_evidence
            if self._state(evidence_id) is not EvidenceState.CONFIRMED
        )
        if missing:
            return Assessment(hypothesis.hypothesis_id, EvidenceState.UNKNOWN, missing, ())

        return Assessment(hypothesis.hypothesis_id, EvidenceState.CONFIRMED, (), ())

    def next_checks(self, hypothesis: Hypothesis) -> tuple[str, ...]:
        assessment = self.assess(hypothesis)
        if assessment.state is EvidenceState.REJECTED:
            return ()
        return tuple(sorted(assessment.missing))

    def minimum_check_plan(
        self,
        hypotheses: Iterable[Hypothesis],
        available_checks: Iterable[DiagnosticCheck],
        *,
        allow_mutating: bool = False,
    ) -> MinimumCheckPlan:
        """Return the non-redundant atomic checks required by all unresolved hypotheses.

        Under the contract that one DiagnosticCheck resolves one evidence_id, the unique union
        of missing required evidence is the minimum complete evidence set. Confirmed or rejected
        hypotheses add no checks. Read-only checks are the default; mutation-capable checks are
        excluded unless explicitly authorized. Ordering is deterministic: read-only, cost, id.
        """
        required: set[str] = set()
        for hypothesis in hypotheses:
            assessment = self.assess(hypothesis)
            if assessment.state is EvidenceState.UNKNOWN:
                required.update(assessment.missing)

        by_id: dict[str, DiagnosticCheck] = {}
        for check in available_checks:
            if check.cost < 0:
                raise ValueError("diagnostic check cost must be non-negative")
            if check.evidence_id not in required:
                continue
            if not allow_mutating and not check.read_only:
                continue
            current = by_id.get(check.evidence_id)
            if current is None or (check.cost, not check.read_only) < (current.cost, not current.read_only):
                by_id[check.evidence_id] = check

        blocked = tuple(sorted(required - set(by_id)))
        ordered = tuple(sorted(by_id.values(), key=lambda item: (not item.read_only, item.cost, item.evidence_id)))
        return MinimumCheckPlan(checks=ordered, blocked_evidence=blocked)

    def _state(self, evidence_id: str) -> EvidenceState:
        item = self._evidence.get(evidence_id)
        return EvidenceState.UNKNOWN if item is None else item.state
