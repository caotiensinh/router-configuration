from __future__ import annotations

import argparse
import getpass
import json
import os
import sys
from pathlib import Path
from typing import Any

from .deployment_profile import DeploymentProfileValidator
from .harness import ExecutionStage, HarnessEngine
from .m02_state_engine import StateEngine
from .m04_multiwan import MultiWanPlanner, WanLink
from .preflight import RouterOSPreflightEvaluator
from .progress import ProgressTracker
from .routeros_discovery import (
    RouterOSDiscoveryCollector,
    RouterOSRestClient,
    normalize_routeros_snapshot,
)
from .routeros_evidence import build_routeros_discovery_evidence


def _load_json(path: str) -> Any:
    return json.loads(Path(path).read_text(encoding="utf-8"))


def _redact(path: str, value: Any) -> Any:
    lowered = path.lower()
    if any(token in lowered for token in ("password", "private_key", "psk", "token", "secret")):
        return "<redacted>"
    return value


def _resolve_password(env_name: str) -> str:
    value = os.environ.get(env_name)
    if value:
        return value
    if not sys.stdin.isatty():
        raise RuntimeError(
            f"{env_name} is not set and password prompting is unavailable in non-interactive mode"
        )
    value = getpass.getpass("RouterOS password: ")
    if not value:
        raise RuntimeError("RouterOS password must not be empty")
    return value


def _write_private_json(path: str, payload: Any) -> None:
    target = Path(path)
    target.parent.mkdir(parents=True, exist_ok=True)
    temporary = target.with_name(f".{target.name}.tmp")
    temporary.write_text(
        json.dumps(payload, indent=2, sort_keys=True, ensure_ascii=False) + "\n",
        encoding="utf-8",
    )
    try:
        temporary.chmod(0o600)
    except OSError:
        pass
    temporary.replace(target)
    try:
        target.chmod(0o600)
    except OSError:
        pass


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


def command_routeros_normalize(args: argparse.Namespace) -> int:
    state = normalize_routeros_snapshot(_load_json(args.fixture))
    print(json.dumps(state, indent=2, sort_keys=True))
    return 0


def command_routeros_discover(args: argparse.Namespace) -> int:
    if (args.allow_insecure_http or args.no_verify_tls) and not args.lab:
        print(
            json.dumps(
                {
                    "ok": False,
                    "error": "insecure transport options require explicit --lab mode",
                },
                sort_keys=True,
            )
        )
        return 2

    try:
        password = _resolve_password(args.password_env)
        client = RouterOSRestClient(
            base_url=args.url,
            username=args.username,
            password=password,
            verify_tls=not args.no_verify_tls,
            allow_insecure_transport=args.allow_insecure_http,
            timeout_seconds=args.timeout,
        )
        report = RouterOSDiscoveryCollector(client).collect_report()
        state = normalize_routeros_snapshot(report.data)
        evidence = build_routeros_discovery_evidence(
            state,
            surface_errors=report.errors,
        )
        _write_private_json(args.output, evidence)
    except Exception as exc:  # noqa: BLE001 - CLI emits safe error class only
        print(
            json.dumps(
                {
                    "ok": False,
                    "error": exc.__class__.__name__,
                    "output": args.output,
                },
                sort_keys=True,
            )
        )
        return 3

    blockers = evidence["capabilities"]["blockers"]
    payload = {
        "ok": not blockers,
        "output": args.output,
        "state_sha256": evidence["state_sha256"],
        "platform": evidence["platform"],
        "failed_surfaces": evidence["collection"]["failed_surfaces"],
        "capability_blockers": blockers,
        "capability_warnings": evidence["capabilities"]["warnings"],
    }
    print(json.dumps(payload, indent=2, sort_keys=True))
    return 0 if not blockers else 4


def command_routeros_preflight(args: argparse.Namespace) -> int:
    result = RouterOSPreflightEvaluator().evaluate(
        _load_json(args.profile),
        _load_json(args.evidence),
    )
    print(json.dumps(result.as_dict(), indent=2, sort_keys=True))
    return 0 if result.ok else 5


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="routerctl")
    subparsers = parser.add_subparsers(dest="command", required=True)

    plan = subparsers.add_parser("plan", help="compare desired and actual JSON state")
    plan.add_argument("--desired", required=True)
    plan.add_argument("--actual", required=True)
    plan.set_defaults(func=command_plan)

    multiwan = subparsers.add_parser("multiwan", help="derive normalized WAN weights from capacity")
    multiwan.add_argument("--wan", action="append", type=_parse_wan, required=True)
    multiwan.set_defaults(func=command_multiwan)

    profile = subparsers.add_parser("profile-check", help="validate a guided deployment profile without changing a router")
    profile.add_argument("--profile", required=True)
    profile.set_defaults(func=command_profile_check)

    workflow = subparsers.add_parser("workflow", help="show guided success/failure criteria for a harness stage")
    workflow.add_argument(
        "--stage",
        choices=[stage.value for stage in ExecutionStage],
        default=ExecutionStage.DISCOVER.value,
    )
    workflow.set_defaults(func=command_workflow)

    progress = subparsers.add_parser("progress", help="report weighted project completion from PROJECT_PROGRESS.json")
    progress.add_argument("--file", default="PROJECT_PROGRESS.json")
    progress.set_defaults(func=command_progress)

    normalize = subparsers.add_parser(
        "routeros-normalize",
        help="normalize an offline RouterOS read-only discovery fixture",
    )
    normalize.add_argument("--fixture", required=True)
    normalize.set_defaults(func=command_routeros_normalize)

    discover = subparsers.add_parser(
        "routeros-discover",
        help="collect sanitized read-only RouterOS state and evidence",
    )
    discover.add_argument("--url", required=True, help="base URL such as https://192.0.2.1")
    discover.add_argument("--username", required=True)
    discover.add_argument(
        "--password-env",
        default="ROUTEROS_PASSWORD",
        help="environment variable containing the RouterOS password",
    )
    discover.add_argument("--output", required=True, help="sanitized evidence JSON path")
    discover.add_argument("--timeout", type=float, default=10.0)
    discover.add_argument("--lab", action="store_true", help="explicitly mark this run as a controlled lab")
    discover.add_argument(
        "--allow-insecure-http",
        action="store_true",
        help="lab only: permit plain HTTP transport",
    )
    discover.add_argument(
        "--no-verify-tls",
        action="store_true",
        help="lab only: disable TLS certificate verification",
    )
    discover.set_defaults(func=command_routeros_discover)

    preflight = subparsers.add_parser(
        "routeros-preflight",
        help="compare a deployment profile with sanitized RouterOS discovery evidence",
    )
    preflight.add_argument("--profile", required=True)
    preflight.add_argument("--evidence", required=True)
    preflight.set_defaults(func=command_routeros_preflight)

    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    return int(args.func(args))


if __name__ == "__main__":
    raise SystemExit(main())
