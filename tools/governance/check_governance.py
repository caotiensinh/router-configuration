#!/usr/bin/env python3
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
from typing import Iterable

REQUIRED_ROOT = ("MASTER_RULES.md", "AGENTS.md", "CONTRIBUTING.md")
REQUIRED_POLICIES = (
    "governance/AI_POLICY.md",
    "governance/KNOWLEDGE_POLICY.md",
    "governance/EXECUTION_POLICY.md",
    "governance/SECURITY_POLICY.md",
    "governance/DOCUMENTATION_POLICY.md",
)
MASTER_MARKERS = (
    "Official vendor documentation is the technical source of truth",
    "NEVER INVENT TECHNICAL TRUTH",
    "NO HUMAN, AI AGENT, SUB-AGENT, AUTOMATION WORKER, OR FUTURE CONTRIBUTOR",
)
PR_CHECKS = (
    "I read the current `MASTER_RULES.md` before this work.",
    "I read `AGENTS.md` and all applicable scoped/vendor rules.",
    "I used approved authoritative sources for vendor-specific technical behavior.",
    "Required tests were executed.",
)


def sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def require_files(root: Path, paths: Iterable[str], errors: list[str]) -> None:
    for rel in paths:
        path = root / rel
        if not path.is_file() or path.stat().st_size == 0:
            errors.append(f"MISSING_REQUIRED_GOVERNANCE_FILE:{rel}")


def check_pr_declaration(errors: list[str]) -> None:
    event_name = os.environ.get("GITHUB_EVENT_NAME", "")
    event_path = os.environ.get("GITHUB_EVENT_PATH", "")
    if event_name != "pull_request" or not event_path:
        return
    payload = json.loads(Path(event_path).read_text(encoding="utf-8"))
    body = str(payload.get("pull_request", {}).get("body") or "")
    for label in PR_CHECKS:
        if f"- [x] {label}" not in body and f"- [X] {label}" not in body:
            errors.append(f"PR_GOVERNANCE_DECLARATION_MISSING:{label}")


def main() -> int:
    parser = argparse.ArgumentParser(description="Validate mandatory project governance bootstrap")
    parser.add_argument("--root", default=".")
    parser.add_argument("--vendor", action="append", default=[])
    parser.add_argument("--json-output")
    args = parser.parse_args()
    root = Path(args.root).resolve()
    errors: list[str] = []

    require_files(root, REQUIRED_ROOT, errors)
    require_files(root, REQUIRED_POLICIES, errors)
    require_files(root, (".github/pull_request_template.md",), errors)
    for vendor in args.vendor:
        require_files(root, (f"vendors/{vendor}/VENDOR_RULES.md",), errors)

    master = root / "MASTER_RULES.md"
    if master.is_file():
        text = master.read_text(encoding="utf-8")
        for marker in MASTER_MARKERS:
            if marker not in text:
                errors.append(f"MASTER_RULE_MARKER_MISSING:{marker}")

    agents = root / "AGENTS.md"
    if agents.is_file() and "MASTER_RULES.md" not in agents.read_text(encoding="utf-8"):
        errors.append("AGENT_RULE_REFERENCE_MISSING")

    readme = root / "README.md"
    if not readme.is_file() or "MASTER_RULES.md" not in readme.read_text(encoding="utf-8"):
        errors.append("README_MASTER_RULE_REFERENCE_MISSING")

    check_pr_declaration(errors)

    evidence = {
        "schema_version": "project-governance-check/1",
        "ok": not errors,
        "errors": errors,
        "master_rules_sha256": sha256(master) if master.is_file() else None,
        "agents_sha256": sha256(agents) if agents.is_file() else None,
        "vendors": {
            vendor: sha256(root / f"vendors/{vendor}/VENDOR_RULES.md")
            if (root / f"vendors/{vendor}/VENDOR_RULES.md").is_file()
            else None
            for vendor in args.vendor
        },
    }
    rendered = json.dumps(evidence, indent=2, sort_keys=True)
    if args.json_output:
        output = Path(args.json_output)
        output.parent.mkdir(parents=True, exist_ok=True)
        output.write_text(rendered + "\n", encoding="utf-8")
    print(rendered)
    return 0 if evidence["ok"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
