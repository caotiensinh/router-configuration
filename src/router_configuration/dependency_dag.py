from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from typing import Iterable


class DependencyDagError(ValueError):
    pass


def _safe(value: object, label: str) -> str:
    text = str(value or "").strip()
    if not text or any(ch in text for ch in ("\n", "\r", "\x00")):
        raise DependencyDagError(f"{label} must be a non-empty single-line value")
    return text


@dataclass(frozen=True)
class DependencyNode:
    operation_id: str
    depends_on: tuple[str, ...]

    def as_dict(self) -> dict[str, object]:
        return {"operation_id": self.operation_id, "depends_on": list(self.depends_on)}


def build_dependency_node(*, operation_id: str, depends_on: Iterable[str] = ()) -> DependencyNode:
    identifier = _safe(operation_id, "operation_id")
    deps = tuple(sorted({_safe(item, "dependency") for item in depends_on}))
    if identifier in deps:
        raise DependencyDagError("operation cannot depend on itself")
    return DependencyNode(identifier, deps)


class DependencyDAG:
    def __init__(self, nodes: Iterable[DependencyNode] = ()) -> None:
        self._nodes: dict[str, DependencyNode] = {}
        for node in nodes:
            self.add(node)

    def add(self, node: DependencyNode) -> None:
        if not isinstance(node, DependencyNode):
            raise DependencyDagError("DAG accepts only DependencyNode")
        if node.operation_id in self._nodes:
            raise DependencyDagError("duplicate operation_id")
        self._nodes[node.operation_id] = node

    def _validate_references(self) -> None:
        known = set(self._nodes)
        missing = sorted({dep for node in self._nodes.values() for dep in node.depends_on if dep not in known})
        if missing:
            raise DependencyDagError(f"unknown dependency references: {missing}")

    def topological_order(self) -> tuple[str, ...]:
        self._validate_references()
        indegree = {node_id: 0 for node_id in self._nodes}
        children: dict[str, set[str]] = {node_id: set() for node_id in self._nodes}
        for node in self._nodes.values():
            indegree[node.operation_id] = len(node.depends_on)
            for dep in node.depends_on:
                children[dep].add(node.operation_id)

        ready = sorted(node_id for node_id, degree in indegree.items() if degree == 0)
        ordered: list[str] = []
        while ready:
            current = ready.pop(0)
            ordered.append(current)
            for child in sorted(children[current]):
                indegree[child] -= 1
                if indegree[child] == 0:
                    ready.append(child)
                    ready.sort()
        if len(ordered) != len(self._nodes):
            raise DependencyDagError("dependency cycle detected")
        return tuple(ordered)

    def as_dict(self) -> dict[str, object]:
        order = self.topological_order()
        payload: dict[str, object] = {
            "schema_version": "network-operation-dependency-dag/1",
            "nodes": [self._nodes[node_id].as_dict() for node_id in sorted(self._nodes)],
            "topological_order": list(order),
            "node_count": len(self._nodes),
            "executable": False,
            "production_write_authority": False,
        }
        raw = json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
        payload["dag_sha256"] = hashlib.sha256(raw).hexdigest()
        return payload
