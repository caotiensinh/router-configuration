from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any

from .deployment_profile import DeploymentProfileValidator
from .harness import ExecutionStage, HarnessEngine
from .m02_state_engine import StateEngine
from .m04_multiwan import MultiWanPlanner, WanLink
from .progress import ProgressTracker


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
    policy = MultiWanPlanner().derive_capacity_weights(args.wan)
    payload = {"weights": dict(policy.weights), "total_weight": policy.total_weight}
    print(json.dumps(payload, indent=2, sort_keys=True))
    return 0


def command_profile_check(args: argparse.Namespace) -> int:
    result = DeploymentProfileValidator().validate(_load_json(args.profile))
    payload: dict[str, Any] = {
        "ok": result.ok,
        "errors": list(result.errors),
        "warnings": list(result.warnings),
        "wan_weights": dict(result.wan_weights),
    }
    if result.deployment_spec is not None:
        spec = result.deployment_spec
        payload["deployment"] = {
            "device_id": spec.device_id,
            "vendor": spec.vendor,
            "management_target": spec.management_target,
            "environment": spec.environment.value,
            "operator_mode": spec.operator_mode.value,
            "site_name": spec.site_name,
            "allow_write": spec.allow_write,
        }
    print(json.dumps(payload, indent=2, sort_keys=True))
    return 0 if result.ok else 2


def command_workflow(args: argparse.Namespace) -> int:
    stage = ExecutionStage(args.stage)
    guide = HarnessEngine().guide(stage)
    payload = {
        "stage": stage.value,
        "title": guide.title,
        "purpose": guide.purpose,
        "success_criteria": guide.success_criteria,
        "failure_action": guide.failure_action,
    }
    print(json.dumps(payload, indent=2, sort_keys=True))
    return 0


def command_progress(args: argparse.Namespace) -> int:
    summary = ProgressTracker().load(args.file)
    payload = {
        "scope": summary.scope,
        "completed_percent": summary.completed_percent,
        "remaining_percent": summary.remaining_percent,
        "total_weight": summary.total_weight,
        "items": {
            "done": summary.items_done,
            "partial": summary.items_partial,
            "not_started": summary.items_not_started,
            "blocked": summary.items_blocked,
        },
        "next_gates": list(summary.next_gates[:5]),
    }
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

    profile = subparsers.add_parser(
        "profile-check",
        help="validate a guided deployment profile without changing a router",
    )
    profile.add_argument("--profile", required=True)
    profile.set_defaults(func=command_profile_check)

    workflow = subparsers.add_parser(
        "workflow",
        help="show guided success/failure criteria for a harness stage",
    )
    workflow.add_argument(
        "--stage",
        choices=[stage.value for stage in ExecutionStage],
        default=ExecutionStage.DISCOVER.value,
    )
    workflow.set_defaults(func=command_workflow)

    progress = subparsers.add_parser(
        "progress",
        help="report weighted project completion from PROJECT_PROGRESS.json",
    )
    progress.add_argument("--file", default="PROJECT_PROGRESS.json")
    progress.set_defaults(func=command_progress)

    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    return int(args.func(args))


if __name__ == "__main__":
    raise SystemExit(main())
