from __future__ import annotations

import hashlib
import json
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from typing import Any, Callable

from .types import OperationKind, RiskLevel


@dataclass(frozen=True)
class ChangeOperation:
    path: str
    kind: OperationKind
    before: Any
    after: Any
    risk: RiskLevel


@dataclass(frozen=True)
class ChangePlan:
    plan_id: str
    operations: tuple[ChangeOperation, ...]

    @property
    def is_noop(self) -> bool:
        return not self.operations

    @property
    def max_risk(self) -> RiskLevel:
        if not self.operations:
            return RiskLevel.READ_ONLY
        return max(operation.risk for operation in self.operations)


RiskClassifier = Callable[[str, OperationKind, Any, Any], RiskLevel]


def default_risk_classifier(
    path: str, kind: OperationKind, before: Any, after: Any
) -> RiskLevel:
    lowered = path.lower()
    critical_tokens = ("management", "default_route", "default-route", "admin_access")
    network_tokens = ("wan", "route", "routing", "firewall", "vpn", "nat")
    bounded_tokens = ("vlan", "qos", "dns", "dhcp")

    if any(token in lowered for token in critical_tokens):
        return RiskLevel.CRITICAL_CHANGE
    if any(token in lowered for token in network_tokens):
        return RiskLevel.NETWORK_CHANGE
    if any(token in lowered for token in bounded_tokens):
        return RiskLevel.BOUNDED_CHANGE
    if kind is OperationKind.DELETE:
        return RiskLevel.NETWORK_CHANGE
    return RiskLevel.BOUNDED_CHANGE


class StateEngine:
    def __init__(self, risk_classifier: RiskClassifier | None = None) -> None:
        self._risk_classifier = risk_classifier or default_risk_classifier

    def build_plan(self, desired: Any, actual: Any) -> ChangePlan:
        operations: list[ChangeOperation] = []
        self._diff(desired, actual, "", operations)
        operations.sort(key=lambda item: (item.path, item.kind.value))

        serializable = [
            {
                "path": operation.path,
                "kind": operation.kind.value,
                "before": operation.before,
                "after": operation.after,
                "risk": int(operation.risk),
            }
            for operation in operations
        ]
        digest = hashlib.sha256(
            json.dumps(serializable, sort_keys=True, separators=(",", ":"), default=str).encode()
        ).hexdigest()[:16]
        return ChangePlan(plan_id=digest, operations=tuple(operations))

    def has_drift(self, desired: Any, actual: Any) -> bool:
        return not self.build_plan(desired, actual).is_noop

    def _append(
        self,
        operations: list[ChangeOperation],
        path: str,
        kind: OperationKind,
        before: Any,
        after: Any,
    ) -> None:
        operations.append(
            ChangeOperation(
                path=path or "$",
                kind=kind,
                before=before,
                after=after,
                risk=self._risk_classifier(path or "$", kind, before, after),
            )
        )

    def _diff(
        self, desired: Any, actual: Any, path: str, operations: list[ChangeOperation]
    ) -> None:
        if isinstance(desired, Mapping) and isinstance(actual, Mapping):
            desired_keys = set(desired)
            actual_keys = set(actual)

            for key in sorted(desired_keys - actual_keys, key=str):
                child = self._child(path, key)
                self._append(operations, child, OperationKind.CREATE, None, desired[key])

            for key in sorted(actual_keys - desired_keys, key=str):
                child = self._child(path, key)
                self._append(operations, child, OperationKind.DELETE, actual[key], None)

            for key in sorted(desired_keys & actual_keys, key=str):
                self._diff(desired[key], actual[key], self._child(path, key), operations)
            return

        if self._is_sequence(desired) and self._is_sequence(actual):
            if list(desired) != list(actual):
                self._append(operations, path, OperationKind.UPDATE, actual, desired)
            return

        if desired != actual:
            self._append(operations, path, OperationKind.UPDATE, actual, desired)

    @staticmethod
    def _child(path: str, key: Any) -> str:
        key_text = str(key)
        return key_text if not path else f"{path}.{key_text}"

    @staticmethod
    def _is_sequence(value: Any) -> bool:
        return isinstance(value, Sequence) and not isinstance(
            value, (str, bytes, bytearray)
        )
