from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any

_ALLOWED_STATUSES = {"done", "partial", "not_started", "blocked"}


@dataclass(frozen=True)
class ProgressSummary:
    scope: str
    completed_percent: int
    remaining_percent: int
    total_weight: int
    items_done: int
    items_partial: int
    items_not_started: int
    items_blocked: int
    next_gates: tuple[dict[str, Any], ...]


class ProgressTracker:
    """Validate and summarize the repository's weighted v1 completion ledger."""

    def load(self, path: str | Path) -> ProgressSummary:
        payload = json.loads(Path(path).read_text(encoding="utf-8"))
        return self.summarize(payload)

    def summarize(self, payload: dict[str, Any]) -> ProgressSummary:
        items = payload.get("items")
        if not isinstance(items, list) or not items:
            raise ValueError("progress ledger must contain a non-empty items list")

        total_weight = 0
        completed = 0
        counts = {status: 0 for status in _ALLOWED_STATUSES}
        next_gates: list[dict[str, Any]] = []
        seen_ids: set[str] = set()

        for item in items:
            if not isinstance(item, dict):
                raise ValueError("each progress item must be an object")
            item_id = str(item.get("id", "")).strip()
            if not item_id or item_id in seen_ids:
                raise ValueError("progress item ids must be non-empty and unique")
            seen_ids.add(item_id)

            status = str(item.get("status", ""))
            if status not in _ALLOWED_STATUSES:
                raise ValueError(f"invalid progress status for {item_id}: {status}")

            weight = int(item.get("weight", 0))
            earned = int(item.get("completed_points", -1))
            if weight <= 0:
                raise ValueError(f"weight must be positive for {item_id}")
            if earned < 0 or earned > weight:
                raise ValueError(f"completed_points must be within 0..weight for {item_id}")
            if status == "done" and earned != weight:
                raise ValueError(f"done item {item_id} must earn its full weight")
            if status == "not_started" and earned != 0:
                raise ValueError(f"not_started item {item_id} must earn zero points")

            total_weight += weight
            completed += earned
            counts[status] += 1
            if status != "done" and item.get("next_gate"):
                next_gates.append(
                    {
                        "id": item_id,
                        "title": str(item.get("title", "")),
                        "remaining_points": weight - earned,
                        "next_gate": str(item["next_gate"]),
                    }
                )

        if total_weight != 100:
            raise ValueError(f"progress weights must total exactly 100, got {total_weight}")

        next_gates.sort(key=lambda item: (-item["remaining_points"], item["id"]))
        return ProgressSummary(
            scope=str(payload.get("scope", "")),
            completed_percent=completed,
            remaining_percent=100 - completed,
            total_weight=total_weight,
            items_done=counts["done"],
            items_partial=counts["partial"],
            items_not_started=counts["not_started"],
            items_blocked=counts["blocked"],
            next_gates=tuple(next_gates),
        )
