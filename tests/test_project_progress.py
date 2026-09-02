from __future__ import annotations

import json
import re
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
PROGRESS = ROOT / "PROJECT_PROGRESS.json"
CHECKLIST = ROOT / "CHECKLIST.md"


def test_weighted_progress_ledger_and_human_status_are_consistent():
    payload = json.loads(PROGRESS.read_text(encoding="utf-8"))
    items = payload["items"]

    ids = [item["id"] for item in items]
    assert len(ids) == len(set(ids))

    total_weight = sum(int(item["weight"]) for item in items)
    completed = sum(int(item["completed_points"]) for item in items)
    assert total_weight == 100
    assert 0 <= completed <= total_weight

    for item in items:
        weight = int(item["weight"])
        earned = int(item["completed_points"])
        assert 0 <= earned <= weight
        if item["status"] == "done":
            assert earned == weight
        elif item["status"] == "partial":
            assert earned < weight

    checklist = CHECKLIST.read_text(encoding="utf-8")
    match = re.search(
        r"\*\*(\d+)% complete / (\d+)% remaining\.\*\*",
        checklist,
    )
    assert match is not None
    checklist_completed = int(match.group(1))
    checklist_remaining = int(match.group(2))
    assert checklist_completed == completed
    assert checklist_remaining == total_weight - completed
    assert checklist_completed + checklist_remaining == 100
