from __future__ import annotations

from dataclasses import dataclass
from math import gcd
from typing import Iterable


@dataclass(frozen=True)
class WanLink:
    name: str
    capacity_mbps: int
    enabled: bool = True

    def __post_init__(self) -> None:
        if not self.name.strip():
            raise ValueError("WAN name must not be empty")
        if self.capacity_mbps <= 0:
            raise ValueError("WAN capacity must be positive")


@dataclass(frozen=True)
class WeightedWanPolicy:
    weights: tuple[tuple[str, int], ...]

    def weight_for(self, wan_name: str) -> int:
        for name, weight in self.weights:
            if name == wan_name:
                return weight
        raise KeyError(wan_name)

    @property
    def total_weight(self) -> int:
        return sum(weight for _, weight in self.weights)


class MultiWanPlanner:
    """Derives vendor-neutral flow-distribution weights from link capacity."""

    def derive_capacity_weights(self, links: Iterable[WanLink]) -> WeightedWanPolicy:
        active = sorted(
            (link for link in links if link.enabled),
            key=lambda link: link.name,
        )
        if not active:
            raise ValueError("at least one enabled WAN is required")

        divisor = active[0].capacity_mbps
        for link in active[1:]:
            divisor = gcd(divisor, link.capacity_mbps)

        weights = tuple(
            (link.name, link.capacity_mbps // divisor)
            for link in active
        )
        return WeightedWanPolicy(weights=weights)

    def allocate_buckets(
        self,
        policy: WeightedWanPolicy,
        *,
        bucket_count: int = 256,
    ) -> tuple[str, ...]:
        if bucket_count <= 0:
            raise ValueError("bucket_count must be positive")

        exact = [
            (name, bucket_count * weight / policy.total_weight)
            for name, weight in policy.weights
        ]
        base_counts = {name: int(value) for name, value in exact}
        assigned = sum(base_counts.values())

        remainders = sorted(
            ((value - int(value), name) for name, value in exact),
            key=lambda item: (-item[0], item[1]),
        )
        for _, name in remainders[: bucket_count - assigned]:
            base_counts[name] += 1

        buckets: list[str] = []
        cursor = {name: 0 for name, _ in policy.weights}
        targets = dict(base_counts)

        # Interleave WAN assignments instead of returning long contiguous ranges.
        while len(buckets) < bucket_count:
            progressed = False
            for name, weight in policy.weights:
                if cursor[name] < targets[name]:
                    quota_ratio = cursor[name] / max(targets[name], 1)
                    other_ratios = [
                        cursor[other] / max(targets[other], 1)
                        for other, _ in policy.weights
                        if cursor[other] < targets[other]
                    ]
                    if not other_ratios or quota_ratio <= min(other_ratios) + (1 / max(weight, 1)):
                        buckets.append(name)
                        cursor[name] += 1
                        progressed = True
                        if len(buckets) == bucket_count:
                            break
            if not progressed:
                break

        if len(buckets) != bucket_count:
            raise RuntimeError("failed to allocate all WAN buckets")
        return tuple(buckets)
