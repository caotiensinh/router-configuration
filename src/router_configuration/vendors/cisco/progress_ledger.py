"""Validate the canonical Cisco IOS XE weighted progress ledger."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
import re
from typing import Any, Mapping

_GATE_STATUS = {"pass", "pending", "blocked"}
_GATE_KIND = {"eng", "accept"}
_ACCEPT_PREFIX = {"live", "human", "physical", "production"}
_SHA40 = re.compile(r"^[0-9a-f]{40}$")
_RUN = re.compile(r"^[0-9]{1,20}$")


class CiscoProgressLedgerError(ValueError):
    pass


def _pct(earned: int, total: int) -> float:
    return round(earned * 100 / total, 1) if total else 0.0


def _evidence_types(evidence: object, *, gate_id: str, repo_root: Path | None) -> set[str]:
    if not isinstance(evidence, list):
        raise CiscoProgressLedgerError(f"{gate_id}: evidence must be a list")
    kinds: set[str] = set()
    for raw in evidence:
        if not isinstance(raw, str) or ":" not in raw:
            raise CiscoProgressLedgerError(f"{gate_id}: malformed evidence reference")
        kind, value = raw.split(":", 1)
        if kind not in {"path", "commit", "run", *_ACCEPT_PREFIX} or not value:
            raise CiscoProgressLedgerError(f"{gate_id}: unsupported evidence reference")
        kinds.add(kind)
        if kind == "path":
            rel = Path(value)
            if rel.is_absolute() or ".." in rel.parts:
                raise CiscoProgressLedgerError(f"{gate_id}: repository path escapes root")
            if repo_root is not None and not (repo_root / rel).exists():
                raise CiscoProgressLedgerError(f"{gate_id}: missing repository evidence: {value}")
        elif kind == "commit" and not _SHA40.fullmatch(value):
            raise CiscoProgressLedgerError(f"{gate_id}: invalid commit SHA")
        elif kind == "run" and not _RUN.fullmatch(value):
            raise CiscoProgressLedgerError(f"{gate_id}: invalid GitHub run id")
    return kinds


def validate_progress_ledger(data: Mapping[str, Any], *, repo_root: str | Path | None = None) -> dict[str, Any]:
    if data.get("schema_version") != "2.0":
        raise CiscoProgressLedgerError("schema_version must be 2.0")

    root = Path(repo_root).resolve() if repo_root is not None else None
    stages = data.get("stages")
    if not isinstance(stages, list) or not stages:
        raise CiscoProgressLedgerError("stages must be non-empty")

    stage_ids: set[str] = set()
    gate_ids: set[str] = set()
    totals = {"eng": 0, "accept": 0}
    earned = {"eng": 0, "accept": 0}
    total_points = 0
    completed_points = 0

    for stage in stages:
        if not isinstance(stage, Mapping):
            raise CiscoProgressLedgerError("stage must be an object")
        sid = str(stage.get("id", ""))
        if not sid or sid in stage_ids:
            raise CiscoProgressLedgerError(f"duplicate or empty stage id: {sid!r}")
        stage_ids.add(sid)
        weight = stage.get("weight")
        if not isinstance(weight, int) or weight <= 0:
            raise CiscoProgressLedgerError(f"{sid}: weight must be positive integer")
        gates = stage.get("gates")
        if not isinstance(gates, list) or not gates:
            raise CiscoProgressLedgerError(f"{sid}: gates must be non-empty")

        sw = 0
        se = 0
        for gate in gates:
            if not isinstance(gate, Mapping):
                raise CiscoProgressLedgerError(f"{sid}: gate must be an object")
            gid = f"{sid}/{gate.get('id', '')}"
            if gid in gate_ids or gid.endswith("/"):
                raise CiscoProgressLedgerError(f"duplicate or empty gate id: {gid}")
            gate_ids.add(gid)
            gw = gate.get("weight")
            kind = gate.get("kind")
            status = gate.get("status")
            points = gate.get("earned")
            if not isinstance(gw, int) or gw <= 0:
                raise CiscoProgressLedgerError(f"{gid}: weight must be positive integer")
            if kind not in _GATE_KIND:
                raise CiscoProgressLedgerError(f"{gid}: invalid gate kind")
            if status not in _GATE_STATUS:
                raise CiscoProgressLedgerError(f"{gid}: invalid gate status")
            expected = gw if status == "pass" else 0
            if points != expected:
                raise CiscoProgressLedgerError(f"{gid}: earned must be {expected} for status {status}")
            kinds = _evidence_types(gate.get("evidence", []), gate_id=gid, repo_root=root)
            if status == "pass" and not kinds:
                raise CiscoProgressLedgerError(f"{gid}: PASS requires evidence")
            if kind == "accept" and status == "pass" and not (kinds & _ACCEPT_PREFIX):
                raise CiscoProgressLedgerError(f"{gid}: acceptance PASS requires live/human/physical/production evidence")
            sw += gw
            se += points
            totals[kind] += gw
            earned[kind] += points

        if sw != weight:
            raise CiscoProgressLedgerError(f"{sid}: gate weights do not equal stage weight")
        if stage.get("earned") != se:
            raise CiscoProgressLedgerError(f"{sid}: stage earned mismatch")
        expected_status = "done" if se == weight else ("in_progress" if se else "not_started")
        if stage.get("status") != expected_status:
            raise CiscoProgressLedgerError(f"{sid}: stage status must be {expected_status}")
        total_points += weight
        completed_points += se

    if total_points != 100:
        raise CiscoProgressLedgerError(f"canonical denominator must be 100, got {total_points}")
    if data.get("completed_points") != completed_points:
        raise CiscoProgressLedgerError("top-level completed_points mismatch")
    if data.get("remaining_points") != 100 - completed_points:
        raise CiscoProgressLedgerError("top-level remaining_points mismatch")
    if data.get("overall_percent") != completed_points:
        raise CiscoProgressLedgerError("overall_percent mismatch")

    budgets = data.get("budgets")
    if not isinstance(budgets, Mapping):
        raise CiscoProgressLedgerError("budgets must be an object")
    for key, kind in (("engineering", "eng"), ("acceptance", "accept")):
        item = budgets.get(key)
        if not isinstance(item, Mapping):
            raise CiscoProgressLedgerError(f"missing budget {key}")
        if item.get("total") != totals[kind] or item.get("earned") != earned[kind]:
            raise CiscoProgressLedgerError(f"{key} budget mismatch")
        if item.get("percent") != _pct(earned[kind], totals[kind]):
            raise CiscoProgressLedgerError(f"{key} percent mismatch")

    rec = data.get("reconciliation")
    if not isinstance(rec, Mapping):
        raise CiscoProgressLedgerError("reconciliation must be an object")
    if rec.get("reconciled_points") != completed_points:
        raise CiscoProgressLedgerError("reconciliation total mismatch")
    previous = rec.get("previous_points")
    delta = rec.get("delta_points")
    if not isinstance(previous, int) or not isinstance(delta, int) or previous + delta != completed_points:
        raise CiscoProgressLedgerError("reconciliation delta mismatch")
    if rec.get("delta_kind") != "measurement_reclassification":
        raise CiscoProgressLedgerError("reconciliation delta kind mismatch")
    if rec.get("new_work_points") != 0:
        raise CiscoProgressLedgerError("measurement reconciliation cannot claim new work")

    if data.get("physical_device_verified") is True:
        c11 = next((s for s in stages if s.get("id") == "C11"), None)
        if not c11 or c11.get("status") != "done":
            raise CiscoProgressLedgerError("physical_device_verified requires C11 done")
    if data.get("production_write_authorized") is True:
        c12 = next((s for s in stages if s.get("id") == "C12"), None)
        if not c12 or c12.get("status") != "done":
            raise CiscoProgressLedgerError("production_write_authorized requires C12 done")

    return {
        "completed": completed_points,
        "remaining": 100 - completed_points,
        "engineering": {"earned": earned["eng"], "total": totals["eng"], "percent": _pct(earned["eng"], totals["eng"])},
        "acceptance": {"earned": earned["accept"], "total": totals["accept"], "percent": _pct(earned["accept"], totals["accept"])},
    }


def load_and_validate(path: str | Path, *, repo_root: str | Path | None = None) -> dict[str, Any]:
    p = Path(path)
    try:
        data = json.loads(p.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise CiscoProgressLedgerError(f"cannot load progress ledger: {exc}") from exc
    if not isinstance(data, Mapping):
        raise CiscoProgressLedgerError("ledger root must be an object")
    return validate_progress_ledger(data, repo_root=repo_root)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("ledger", nargs="?", default="CISCO_PROGRESS.json")
    parser.add_argument("--repo-root", default=".")
    args = parser.parse_args()
    print(json.dumps(load_and_validate(args.ledger, repo_root=args.repo_root), sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
