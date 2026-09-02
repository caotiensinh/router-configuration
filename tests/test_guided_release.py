from __future__ import annotations

import json
from pathlib import Path

from router_configuration.guided_release import GuidedReleaseError, build_guided_release_workspace
from router_configuration.profile_builder import GuidedProfileRequest
from router_configuration.routerctl import main


def _request() -> GuidedProfileRequest:
    return GuidedProfileRequest(
        site_name="R&D Center",
        device_id="router-lab-001",
        management_target="192.0.2.10",
        environment="lab",
    )


def test_build_guided_release_workspace_is_planning_only(tmp_path: Path) -> None:
    workspace = tmp_path / "site"
    result = build_guided_release_workspace(request=_request(), workspace=workspace)

    payload = result.as_dict()
    assert payload["ok"] is True
    assert payload["allow_write"] is False
    assert payload["secrets_resolved"] is False
    assert payload["transport_present"] is False
    assert payload["apply_available"] is False
    assert payload["write_authorized"] is False

    profile = json.loads((workspace / "profile.json").read_text(encoding="utf-8"))
    ir = json.loads((workspace / "safe-subset-ir.json").read_text(encoding="utf-8"))
    start_here = (workspace / "START_HERE.md").read_text(encoding="utf-8")

    assert profile["allow_write"] is False
    assert ir["vendor_commands_present"] is False
    assert ir["write_transport_present"] is False
    assert "planning-only" in start_here
    assert "no RouterOS transport" in start_here
    assert "physical-router mutation remains disabled" in start_here


def test_guided_start_cli_creates_complete_workspace(tmp_path: Path, capsys) -> None:
    workspace = tmp_path / "guided"
    rc = main(
        [
            "guided-start",
            "--workspace",
            str(workspace),
            "--site-name",
            "R&D Center",
            "--device-id",
            "router-lab-002",
            "--management-target",
            "192.0.2.20",
            "--environment",
            "lab",
        ]
    )

    assert rc == 0
    output = json.loads(capsys.readouterr().out)
    assert output["ok"] is True
    assert output["claim"] == "guided_workspace_ready"
    assert output["transport_present"] is False
    assert output["apply_available"] is False
    assert output["write_authorized"] is False
    assert {path.name for path in workspace.iterdir()} == {
        "profile.json",
        "safe-subset-ir.json",
        "START_HERE.md",
    }


def test_guided_workspace_rejects_file_target(tmp_path: Path) -> None:
    target = tmp_path / "not-a-directory"
    target.write_text("occupied", encoding="utf-8")

    try:
        build_guided_release_workspace(request=_request(), workspace=target)
    except GuidedReleaseError as exc:
        assert "not a directory" in str(exc)
    else:  # pragma: no cover - explicit safety assertion
        raise AssertionError("file target must be rejected")


def test_guided_workspace_contains_no_secret_values_or_runtime_capability(tmp_path: Path) -> None:
    workspace = tmp_path / "site"
    build_guided_release_workspace(request=_request(), workspace=workspace)

    serialized = "\n".join(
        path.read_text(encoding="utf-8")
        for path in sorted(workspace.iterdir())
    ).lower()
    assert "private_key" not in serialized
    assert "preshared_key" not in serialized
    assert '"password"' not in serialized
    assert '"token"' not in serialized
    assert "write_authorized=true" not in serialized
