from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from typing import Mapping


class EvidenceState(str, Enum):
    UNKNOWN = "unknown"
    PASS = "pass"
    FAIL = "fail"


@dataclass(frozen=True)
class TroubleshootingNode:
    name: str
    feature: str
    depends_on: tuple[str, ...] = ()


@dataclass(frozen=True)
class TroubleshootingAssessment:
    candidates: tuple[str, ...]
    unresolved: tuple[str, ...]

    @property
    def root_cause_confirmed(self) -> bool:
        return False


def internet_access_graph() -> tuple[TroubleshootingNode, ...]:
    """Vendor-neutral causal checkpoints mapped only to MikroTik feature tags.

    This graph intentionally does not contain RouterOS CLI syntax. It is used to
    choose evidence collection areas, not to declare a root cause automatically.
    """

    return (
        TroubleshootingNode("device_inventory", "inventory"),
        TroubleshootingNode("interface_state", "interface", ("device_inventory",)),
        TroubleshootingNode("addressing", "internet", ("interface_state",)),
        TroubleshootingNode("routing", "routing", ("addressing",)),
        TroubleshootingNode("policy", "firewall", ("routing",)),
        TroubleshootingNode("reachability", "diagnostic", ("routing",)),
    )


def assess_graph(
    graph: tuple[TroubleshootingNode, ...],
    evidence: Mapping[str, EvidenceState | str],
) -> TroubleshootingAssessment:
    states = {
        name: value if isinstance(value, EvidenceState) else EvidenceState(str(value))
        for name, value in evidence.items()
    }
    candidates: list[str] = []
    unresolved: list[str] = []
    known_nodes = {node.name for node in graph}
    unknown_keys = set(states) - known_nodes
    if unknown_keys:
        raise ValueError("evidence contains unknown troubleshooting nodes")

    for node in graph:
        state = states.get(node.name, EvidenceState.UNKNOWN)
        if state is EvidenceState.UNKNOWN:
            unresolved.append(node.name)
            continue
        if state is EvidenceState.FAIL:
            prereqs = [states.get(dep, EvidenceState.UNKNOWN) for dep in node.depends_on]
            if all(item is EvidenceState.PASS for item in prereqs):
                candidates.append(node.name)
    return TroubleshootingAssessment(tuple(candidates), tuple(unresolved))
