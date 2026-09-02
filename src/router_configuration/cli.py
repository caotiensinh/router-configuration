from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any

from .m02_state_engine import StateEngine
from .m04_multiwan import MultiWanPlanner, WanLink


def _load_json(path: str) -> Any:
    return json.loads(Path(path).read_text(encoding="utf-8"))


def _redact(path: str, value: Any) -> Any:
    lowered = path.lower()
    if any(token in lowered for token in ("password", "private_key", "psk", "token", "secret")):
        return "<redacted>"
    return value


def command_plan(args: argparse.Namespace) -> int:
    desired = _load_json(args.desired)
    actual = _load_json(args.actual)
    plan = StateEngine().build_plan(desired, actual)
    payload = {
        "plan_id": plan.plan_id,
        "max_risk": int(plan.max_risk),
        "operation_count": len(plan.operations),
        "operations": [
            {
                "path": item.path,
                "kind": item.kind.value,
                "risk": int(item.risk),
                "before": _redact(item.path, item.before),
                "after": _redact(item.path, item.after),
            }
            for item in plan.operations
        ],
    }
    print(json.dumps(payload, indent=2, sort_keys=True, default=str))
    return 0


def _parse_wan(value: str) -> WanLink:
    try:
        name, capacity = value.split("=", 1)
        return WanLink(name=name, capacity_mbps=int(capacity))
    except (ValueError, TypeError) as exc:
        raise argparse.ArgumentTypeError("WAN must use NAME=CAPACITY_MBPS") from exc


def command_multiwan(args: argparse.Namespace) -> int:
    planner = MultiWanPlanner()
    policy = planner.derive_capacity_weights(args.wan)
    payload = {"weights": dict(policy.weights), "total_weight": policy.total_weight}
    print(json.dumps(payload, indent=2, sort_keys=True))
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="routerctl")
    subparsers = parser.add_subparsers(dest="command", required=True)

    plan = subparsers.add_parser("plan", help="compare desired and actual JSON state")
    plan.add_argument("--desired", required=True)
    plan.add_argument("--actual", required=True)
    plan.set_defaults(func=command_plan)

    multiwan = subparsers.add_parser(
        "multiwan",
        help="derive normalized WAN weights from capacity",
    )
    multiwan.add_argument("--wan", action="append", type=_parse_wan, required=True)
    multiwan.set_defaults(func=command_multiwan)

    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    return int(args.func(args))


if __name__ == "__main__":
    raise SystemExit(main())
