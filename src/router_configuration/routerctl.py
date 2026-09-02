from __future__ import annotations

import argparse
import hashlib
import json
import sys
from pathlib import Path
from typing import Any

from .cli import main as legacy_main
from .routeros_generation import generate_routeros_plan


def _load_json(path: str) -> Any:
    return json.loads(Path(path).read_text(encoding="utf-8"))


def _write_private_text(path: str, content: str) -> None:
    target = Path(path)
    target.parent.mkdir(parents=True, exist_ok=True)
    temporary = target.with_name(f".{target.name}.tmp")
    temporary.write_text(content, encoding="utf-8")
    try:
        temporary.chmod(0o600)
    except OSError:
        pass
    temporary.replace(target)
    try:
        target.chmod(0o600)
    except OSError:
        pass


def _write_private_json(path: str, payload: Any) -> None:
    _write_private_text(
        path,
        json.dumps(payload, indent=2, sort_keys=True, ensure_ascii=False) + "\n",
    )


def _render_script(plan: dict[str, Any]) -> str:
    commands = plan.get("commands", [])
    if not isinstance(commands, list):
        raise ValueError("render plan commands must be a list")
    lines: list[str] = []
    for item in commands:
        if not isinstance(item, dict):
            raise ValueError("render plan contains a non-object command")
        command = str(item.get("command") or "").strip()
        if not command:
            raise ValueError("render plan contains an empty command")
        lines.append(command)
    return "\n".join(lines) + ("\n" if lines else "")


def command_routeros_render(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(
        prog="routerctl routeros-render",
        description=(
            "Generate offline RouterOS artifacts from a bound profile, safe-subset IR, "
            "and verified discovery evidence. This command has no transport or apply path."
        ),
    )
    parser.add_argument("--profile", required=True)
    parser.add_argument("--ir", required=True)
    parser.add_argument("--evidence", required=True)
    parser.add_argument("--output", required=True, help="generation result JSON path")
    parser.add_argument("--script-output", help="optional generated RouterOS .rsc path")
    args = parser.parse_args(argv)

    try:
        result = generate_routeros_plan(
            profile=_load_json(args.profile),
            ir=_load_json(args.ir),
            evidence=_load_json(args.evidence),
        )
        payload = result.as_dict()
        _write_private_json(args.output, payload)
    except Exception as exc:  # noqa: BLE001 - bounded offline CLI error
        print(
            json.dumps(
                {
                    "ok": False,
                    "claim": "routeros_generation_failed",
                    "error": exc.__class__.__name__,
                    "output": args.output,
                    "transport_present": False,
                    "apply_available": False,
                    "write_authorized": False,
                },
                sort_keys=True,
            )
        )
        return 7

    if not result.ok or result.render_plan is None:
        summary = {
            "ok": False,
            "claim": payload["claim"],
            "errors": payload["errors"],
            "warnings": payload["warnings"],
            "output": args.output,
            "script_output": None,
            "transport_present": False,
            "apply_available": False,
            "write_authorized": False,
        }
        print(json.dumps(summary, indent=2, sort_keys=True))
        return 7

    plan = dict(result.render_plan)
    script_output = None
    script_sha256 = None
    if args.script_output:
        script = _render_script(plan)
        _write_private_text(args.script_output, script)
        script_output = args.script_output
        script_sha256 = hashlib.sha256(script.encode("utf-8")).hexdigest()

    summary = {
        "ok": True,
        "claim": payload["claim"],
        "generation_complete": bool(plan.get("complete")),
        "render_claim": plan.get("claim"),
        "command_count": len(plan.get("commands", [])),
        "blocked_operations": plan.get("blocked_operations", []),
        "render_sha256": plan.get("render_sha256"),
        "script_sha256": script_sha256,
        "output": args.output,
        "script_output": script_output,
        "secrets_resolved": False,
        "transport_present": False,
        "apply_available": False,
        "write_authorized": False,
    }
    print(json.dumps(summary, indent=2, sort_keys=True))
    return 0


def main(argv: list[str] | None = None) -> int:
    args = list(sys.argv[1:] if argv is None else argv)
    if args and args[0] == "routeros-render":
        return command_routeros_render(args[1:])
    return int(legacy_main(args))


if __name__ == "__main__":
    raise SystemExit(main())
