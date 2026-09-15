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


class EvidenceRCAGraph:
    """Deterministic, fail-closed RCA evaluator.

    A hypothesis is CONFIRMED only when all required evidence is CONFIRMED and no
    contradicting evidence is CONFIRMED. Missing or UNKNOWN required evidence
    keeps the hypothesis UNKNOWN. A confirmed contradiction REJECTS it.
    """

    def __init__(self, evidence: Iterable[Evidence] = ()) -> None:
        self._evidence = {item.evidence_id: item for item in evidence}

    def assess(self, hypothesis: Hypothesis) -> Assessment:
        contradictions = tuple(
            evidence_id
            for evidence_id in hypothesis.contradicting_evidence
            if self._state(evidence_id) is EvidenceState.CONFIRMED
        )
        if contradictions:
            return Assessment(
                hypothesis_id=hypothesis.hypothesis_id,
                state=EvidenceState.REJECTED,
                missing=(),
                contradictions=contradictions,
            )

        missing = tuple(
            evidence_id
            for evidence_id in hypothesis.required_evidence
            if self._state(evidence_id) is not EvidenceState.CONFIRMED
        )
        if missing:
            return Assessment(
                hypothesis_id=hypothesis.hypothesis_id,
                state=EvidenceState.UNKNOWN,
                missing=missing,
                contradictions=(),
            )

        return Assessment(
            hypothesis_id=hypothesis.hypothesis_id,
            state=EvidenceState.CONFIRMED,
            missing=(),
            contradictions=(),
        )

    def next_checks(self, hypothesis: Hypothesis) -> tuple[str, ...]:
        """Return the smallest deterministic set of unresolved required checks."""
        assessment = self.assess(hypothesis)
        if assessment.state is EvidenceState.REJECTED:
            return ()
        return tuple(sorted(assessment.missing))

    def _state(self, evidence_id: str) -> EvidenceState:
        item = self._evidence.get(evidence_id)
        return EvidenceState.UNKNOWN if item is None else item.state
