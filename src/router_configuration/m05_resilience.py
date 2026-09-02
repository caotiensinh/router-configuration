from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from typing import Iterable


class ProbeKind(str, Enum):
    GATEWAY = "gateway"
    INTERNET = "internet"
    DNS = "dns"
    HTTPS = "https"


class WanHealthState(str, Enum):
    HEALTHY = "healthy"
    DEGRADED = "degraded"
    DOWN = "down"


@dataclass(frozen=True)
class ProbeResult:
    kind: ProbeKind
    success: bool
    weight: float = 1.0
    latency_ms: float | None = None

    def __post_init__(self) -> None:
        if self.weight <= 0:
            raise ValueError("probe weight must be positive")
        if self.latency_ms is not None and self.latency_ms < 0:
            raise ValueError("latency cannot be negative")


@dataclass(frozen=True)
class HealthPolicy:
    down_below: float = 40.0
    healthy_at_or_above: float = 80.0

    def __post_init__(self) -> None:
        if not 0 <= self.down_below < self.healthy_at_or_above <= 100:
            raise ValueError("health thresholds must satisfy 0 <= down < healthy <= 100")


@dataclass(frozen=True)
class HealthDecision:
    score: float
    previous: WanHealthState
    current: WanHealthState
    changed: bool


class ResilienceEngine:
    def score(self, probes: Iterable[ProbeResult]) -> float:
        items = tuple(probes)
        if not items:
            raise ValueError("at least one probe result is required")

        total_weight = sum(item.weight for item in items)
        successful_weight = sum(item.weight for item in items if item.success)
        return round(successful_weight * 100.0 / total_weight, 2)

    def decide(
        self,
        previous: WanHealthState,
        score: float,
        policy: HealthPolicy | None = None,
    ) -> HealthDecision:
        cfg = policy or HealthPolicy()
        if not 0 <= score <= 100:
            raise ValueError("score must be between 0 and 100")

        if previous is WanHealthState.DOWN:
            if score >= cfg.healthy_at_or_above:
                current = WanHealthState.HEALTHY
            else:
                current = WanHealthState.DOWN
        else:
            if score < cfg.down_below:
                current = WanHealthState.DOWN
            elif score >= cfg.healthy_at_or_above:
                current = WanHealthState.HEALTHY
            else:
                current = WanHealthState.DEGRADED

        return HealthDecision(
            score=score,
            previous=previous,
            current=current,
            changed=current is not previous,
        )
