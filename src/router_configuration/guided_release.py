from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Mapping

from .deployment_profile import DeploymentProfileValidator
from .profile_builder import GuidedProfileBuilder, GuidedProfileRequest
from .safe_subset_ir import SafeSubsetCompiler


class GuidedReleaseError(ValueError):
    pass


@dataclass(frozen=True)
class GuidedReleaseResult:
    workspace: str
    profile_path: str
    ir_path: str
    start_here_path: str
    profile: Mapping[str, Any]
    ir: Mapping[str, Any]

    def as_dict(self) -> dict[str, Any]:
        return {
            "ok": True,
            "claim": "guided_workspace_ready",
            "workspace": self.workspace,
            "profile_path": self.profile_path,
            "ir_path": self.ir_path,
            "start_here_path": self.start_here_path,
            "allow_write": False,
            "secrets_resolved": False,
            "transport_present": False,
            "apply_available": False,
            "write_authorized": False,
            "next_gate": "run verified RouterOS read-only discovery and preflight before any configuration workflow",
        }


def _write_private_json(path: Path, payload: Mapping[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(f".{path.name}.tmp")
    temporary.write_text(
        json.dumps(payload, indent=2, sort_keys=True, ensure_ascii=False) + "\n",
        encoding="utf-8",
    )
    try:
        temporary.chmod(0o600)
    except OSError:
        pass
    temporary.replace(path)
    try:
        path.chmod(0o600)
    except OSError:
        pass


def _write_start_here(path: Path, *, profile_name: str, ir_name: str) -> None:
    content = f"""# Router Configuration - START HERE\n\nThis workspace is **planning-only**. It cannot write to a router.\n\n## Files\n\n- `{profile_name}` - beginner-safe deployment profile\n- `{ir_name}` - deterministic vendor-neutral safe-subset IR\n\n## Next gate\n\n1. Review `{profile_name}`.\n2. Run `routerctl profile-check --profile {profile_name}`.\n3. Run read-only RouterOS discovery and save verified evidence.\n4. Run `routerctl routeros-preflight` against the exact profile and evidence.\n5. Generate RouterOS artifacts only after preflight passes.\n\n## Safety boundary\n\n- `allow_write=false`\n- no secret values are stored in this workspace\n- no RouterOS transport is created by guided-start\n- no apply or rollback command is exposed\n- physical-router mutation remains disabled until the separate transactional runtime gate is accepted\n"""
    path.write_text(content, encoding="utf-8")


def build_guided_release_workspace(
    *,
    request: GuidedProfileRequest,
    workspace: str | Path,
) -> GuidedReleaseResult:
    target = Path(workspace)
    if target.exists() and not target.is_dir():
        raise GuidedReleaseError("workspace path exists and is not a directory")
    target.mkdir(parents=True, exist_ok=True)

    profile = GuidedProfileBuilder().build(request)
    validation = DeploymentProfileValidator().validate(profile)
    if not validation.ok:
        raise GuidedReleaseError("guided profile did not pass validation")
    if bool(profile.get("safety", {}).get("allow_write")):
        raise GuidedReleaseError("guided workspace must keep allow_write=false")

    ir = SafeSubsetCompiler().compile(profile).as_dict()
    if ir.get("vendor_commands_present") is not False:
        raise GuidedReleaseError("guided workspace IR must not contain vendor commands")
    if ir.get("write_transport_present") is not False:
        raise GuidedReleaseError("guided workspace IR must not contain write transport")

    profile_path = target / "profile.json"
    ir_path = target / "safe-subset-ir.json"
    start_here_path = target / "START_HERE.md"
    _write_private_json(profile_path, profile)
    _write_private_json(ir_path, ir)
    _write_start_here(
        start_here_path,
        profile_name=profile_path.name,
        ir_name=ir_path.name,
    )

    return GuidedReleaseResult(
        workspace=str(target),
        profile_path=str(profile_path),
        ir_path=str(ir_path),
        start_here_path=str(start_here_path),
        profile=profile,
        ir=ir,
    )
