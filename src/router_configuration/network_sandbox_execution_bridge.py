from __future__ import annotations

import hashlib
import hmac
import json
import os
import subprocess
import tempfile
import tomllib
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Mapping

from .device_backend import EvidenceClass
from .network_sandbox_acceptance import NETWORK_SANDBOX_REPOSITORY
from .network_sandbox_scenario_compiler import (
    COMPILED_SCHEMA,
    validate_compiled_network_sandbox_scenario,
)


EXECUTION_EVIDENCE_SCHEMA = "network-sandbox-execution-evidence/1"
ROUTER_CONFIGURATION_REPOSITORY = "caotiensinh/router-configuration"

_ALLOWED_ENV = frozenset(
    {
        "PATH",
        "HOME",
        "USERPROFILE",
        "SYSTEMROOT",
        "WINDIR",
        "TEMP",
        "TMP",
        "TMPDIR",
        "LANG",
        "LC_ALL",
        "COMSPEC",
        "PATHEXT",
        "VIRTUAL_ENV",
    }
)


class NetworkSandboxExecutionError(RuntimeError):
    """Raised when sandbox execution or provenance verification fails closed."""


@dataclass(frozen=True)
class NetworkSandboxExecutionBinding:
    router_configuration_root: str
    router_configuration_sha: str
    network_sandbox_root: str
    network_sandbox_sha: str
    python_executable: str
    git_executable: str
    timeout_seconds: int = 60


@dataclass(frozen=True)
class NetworkSandboxExecutionEvidence:
    payload: Mapping[str, Any]

    def as_dict(self) -> dict[str, Any]:
        return dict(self.payload)


def _canonical_json_bytes(value: Any) -> bytes:
    return json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        default=str,
    ).encode("utf-8")


def _canonical_sha256(value: Any) -> str:
    return hashlib.sha256(_canonical_json_bytes(value)).hexdigest()


def _bytes_sha256(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def _require_sha40(value: object, label: str) -> str:
    text = str(value or "").strip().lower()
    if len(text) != 40 or any(ch not in "0123456789abcdef" for ch in text):
        raise NetworkSandboxExecutionError(
            f"{label} must be a lowercase 40-character git SHA"
        )
    return text


def _require_absolute_file(value: str, label: str) -> Path:
    path = Path(value)
    if not path.is_absolute():
        raise NetworkSandboxExecutionError(f"{label} must be an absolute path")
    if not path.is_file():
        raise NetworkSandboxExecutionError(f"{label} does not exist as a file")
    return path.resolve()


def _require_absolute_directory(value: str, label: str) -> Path:
    path = Path(value)
    if not path.is_absolute():
        raise NetworkSandboxExecutionError(f"{label} must be an absolute path")
    if not path.is_dir():
        raise NetworkSandboxExecutionError(f"{label} does not exist as a directory")
    return path.resolve()


def _validate_timeout(value: object) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or not 1 <= value <= 300:
        raise NetworkSandboxExecutionError(
            "timeout_seconds must be an integer from 1 through 300"
        )
    return value


def _safe_environment() -> dict[str, str]:
    env = {
        key: value
        for key, value in os.environ.items()
        if key in _ALLOWED_ENV and isinstance(value, str)
    }
    env["PYTHONNOUSERSITE"] = "1"
    env["PYTHONDONTWRITEBYTECODE"] = "1"
    env.pop("PYTHONPATH", None)
    env.pop("PYTHONHOME", None)
    return env


def _project_identity(root: Path, *, expected_name: str, label: str) -> str:
    pyproject = root / "pyproject.toml"
    if not pyproject.is_file():
        raise NetworkSandboxExecutionError(f"{label} is missing pyproject.toml")
    try:
        document = tomllib.loads(pyproject.read_text(encoding="utf-8"))
    except (OSError, tomllib.TOMLDecodeError) as exc:
        raise NetworkSandboxExecutionError(
            f"{label} pyproject.toml cannot be read"
        ) from exc
    project = document.get("project")
    if not isinstance(project, Mapping):
        raise NetworkSandboxExecutionError(f"{label} pyproject project table is missing")
    name = str(project.get("name") or "").strip()
    if name != expected_name:
        raise NetworkSandboxExecutionError(
            f"{label} project name must be {expected_name}"
        )
    version = str(project.get("version") or "").strip()
    if not version:
        raise NetworkSandboxExecutionError(f"{label} project version is missing")
    return version


def _run_process(
    args: list[str],
    *,
    cwd: Path,
    timeout_seconds: int,
    env: Mapping[str, str],
) -> subprocess.CompletedProcess[str]:
    try:
        return subprocess.run(
            args,
            cwd=str(cwd),
            env=dict(env),
            capture_output=True,
            text=True,
            timeout=timeout_seconds,
            check=False,
            shell=False,
        )
    except subprocess.TimeoutExpired as exc:
        raise NetworkSandboxExecutionError(
            f"process timed out after {timeout_seconds}s"
        ) from exc
    except OSError as exc:
        raise NetworkSandboxExecutionError("failed to start sandbox process") from exc


def _verify_git_head(
    *,
    git_executable: Path,
    root: Path,
    expected_sha: str,
    timeout_seconds: int,
    env: Mapping[str, str],
    label: str,
) -> None:
    result = _run_process(
        [str(git_executable), "-C", str(root), "rev-parse", "HEAD"],
        cwd=root,
        timeout_seconds=timeout_seconds,
        env=env,
    )
    if result.returncode != 0:
        raise NetworkSandboxExecutionError(
            f"{label} git HEAD verification failed"
        )
    observed = str(result.stdout or "").strip().lower()
    if observed != expected_sha:
        raise NetworkSandboxExecutionError(
            f"{label} git HEAD mismatch: expected {expected_sha}, observed {observed or '<empty>'}"
        )


def _parse_json_output(stdout: str, label: str) -> Mapping[str, Any]:
    text = str(stdout or "").strip()
    if not text:
        raise NetworkSandboxExecutionError(f"{label} produced no JSON output")
    try:
        payload = json.loads(text)
    except json.JSONDecodeError as exc:
        raise NetworkSandboxExecutionError(
            f"{label} output is not valid JSON"
        ) from exc
    if not isinstance(payload, Mapping):
        raise NetworkSandboxExecutionError(f"{label} JSON output must be an object")
    return payload


def _validate_runtime_result(
    payload: Mapping[str, Any],
    *,
    returncode: int,
) -> tuple[bool, Mapping[str, Any], Mapping[str, Any], list[Any]]:
    scenario_pass = payload.get("pass")
    if type(scenario_pass) is not bool:
        raise NetworkSandboxExecutionError("sandbox run result pass must be boolean")

    summary = payload.get("summary")
    if not isinstance(summary, Mapping):
        raise NetworkSandboxExecutionError("sandbox run result summary must be an object")
    counts: dict[str, int] = {}
    for field in ("total", "passed", "failed"):
        value = summary.get(field)
        if isinstance(value, bool) or not isinstance(value, int) or value < 0:
            raise NetworkSandboxExecutionError(
                f"sandbox run summary.{field} must be a non-negative integer"
            )
        counts[field] = value
    if counts["total"] < 1:
        raise NetworkSandboxExecutionError("sandbox run must execute at least one test")
    if counts["passed"] + counts["failed"] != counts["total"]:
        raise NetworkSandboxExecutionError("sandbox run summary accounting mismatch")
    if scenario_pass != (counts["failed"] == 0):
        raise NetworkSandboxExecutionError("sandbox run pass flag disagrees with summary")

    if scenario_pass and returncode != 0:
        raise NetworkSandboxExecutionError(
            "sandbox returned non-zero for a passing scenario"
        )
    if not scenario_pass and returncode != 1:
        raise NetworkSandboxExecutionError(
            "sandbox failed scenario must return exit code 1"
        )

    snapshot = payload.get("snapshot")
    if not isinstance(snapshot, Mapping):
        raise NetworkSandboxExecutionError("sandbox run snapshot must be an object")
    tests = payload.get("tests")
    if not isinstance(tests, list) or len(tests) != counts["total"]:
        raise NetworkSandboxExecutionError(
            "sandbox run tests must match summary.total"
        )
    return scenario_pass, dict(summary), snapshot, tests


def _validate_binding(
    binding: NetworkSandboxExecutionBinding,
    *,
    compiled_record: Mapping[str, Any],
) -> tuple[Path, Path, Path, Path, int, str]:
    router_sha = _require_sha40(
        binding.router_configuration_sha, "router_configuration_sha"
    )
    sandbox_sha = _require_sha40(binding.network_sandbox_sha, "network_sandbox_sha")
    timeout = _validate_timeout(binding.timeout_seconds)

    router_root = _require_absolute_directory(
        binding.router_configuration_root, "router_configuration_root"
    )
    sandbox_root = _require_absolute_directory(
        binding.network_sandbox_root, "network_sandbox_root"
    )
    python_executable = _require_absolute_file(
        binding.python_executable, "python_executable"
    )
    git_executable = _require_absolute_file(binding.git_executable, "git_executable")

    compiled_sandbox_sha = str(compiled_record.get("network_sandbox_sha") or "").strip().lower()
    if compiled_sandbox_sha != sandbox_sha:
        raise NetworkSandboxExecutionError(
            "compiled scenario Network Sandbox SHA does not match execution binding"
        )

    _project_identity(
        router_root,
        expected_name="router-configuration",
        label="router_configuration_root",
    )
    sandbox_version = _project_identity(
        sandbox_root,
        expected_name="network-sandbox-runtime",
        label="network_sandbox_root",
    )
    env = _safe_environment()
    _verify_git_head(
        git_executable=git_executable,
        root=router_root,
        expected_sha=router_sha,
        timeout_seconds=timeout,
        env=env,
        label="router_configuration_root",
    )
    _verify_git_head(
        git_executable=git_executable,
        root=sandbox_root,
        expected_sha=sandbox_sha,
        timeout_seconds=timeout,
        env=env,
        label="network_sandbox_root",
    )
    return (
        router_root,
        sandbox_root,
        python_executable,
        git_executable,
        timeout,
        sandbox_version,
    )


def execute_compiled_network_sandbox_scenario(
    compiled_record: Mapping[str, Any],
    *,
    binding: NetworkSandboxExecutionBinding,
) -> NetworkSandboxExecutionEvidence:
    """Run one compiled scenario against an exact checked-out Network Sandbox runtime.

    The bridge executes no shell, accepts no credentials, verifies both repository
    HEADs before execution, and keeps evidence at VIRTUAL_VERIFIED ceiling.
    Scenario assertion failures are returned as valid negative evidence; runtime
    or provenance failures raise and stop processing.
    """

    if not isinstance(compiled_record, Mapping):
        raise NetworkSandboxExecutionError("compiled_record must be an object")
    if compiled_record.get("schema_version") != COMPILED_SCHEMA:
        raise NetworkSandboxExecutionError("unsupported compiled scenario record")
    try:
        validate_compiled_network_sandbox_scenario(compiled_record)
    except ValueError as exc:
        raise NetworkSandboxExecutionError(
            "compiled scenario validation failed"
        ) from exc

    (
        router_root,
        sandbox_root,
        python_executable,
        _git_executable,
        timeout_seconds,
        sandbox_version,
    ) = _validate_binding(binding, compiled_record=compiled_record)

    scenario = compiled_record.get("scenario")
    assert isinstance(scenario, Mapping)
    scenario_bytes = _canonical_json_bytes(scenario)
    scenario_file_sha256 = _bytes_sha256(scenario_bytes)
    expected_scenario_sha256 = str(compiled_record.get("scenario_sha256") or "")
    if not hmac.compare_digest(scenario_file_sha256, expected_scenario_sha256):
        raise NetworkSandboxExecutionError(
            "serialized scenario digest does not match compiled scenario digest"
        )

    env = _safe_environment()
    with tempfile.TemporaryDirectory(prefix="router-config-network-sandbox-") as temp_dir:
        scenario_path = Path(temp_dir) / "scenario.json"
        scenario_path.write_bytes(scenario_bytes)

        validate_result = _run_process(
            [
                str(python_executable),
                "-m",
                "network_sandbox.cli",
                "validate",
                str(scenario_path),
            ],
            cwd=sandbox_root,
            timeout_seconds=timeout_seconds,
            env=env,
        )
        if validate_result.returncode != 0:
            raise NetworkSandboxExecutionError(
                "network-sandbox validate returned non-zero"
            )
        validation_payload = _parse_json_output(
            validate_result.stdout, "network-sandbox validate"
        )
        if validation_payload.get("valid") is not True:
            raise NetworkSandboxExecutionError(
                "network-sandbox validate did not confirm valid=true"
            )

        run_result = _run_process(
            [
                str(python_executable),
                "-m",
                "network_sandbox.cli",
                "run",
                str(scenario_path),
            ],
            cwd=sandbox_root,
            timeout_seconds=timeout_seconds,
            env=env,
        )
        if run_result.returncode not in {0, 1}:
            raise NetworkSandboxExecutionError(
                f"network-sandbox run returned unsupported exit code {run_result.returncode}"
            )
        raw_payload = _parse_json_output(run_result.stdout, "network-sandbox run")
        scenario_pass, summary, snapshot, _tests = _validate_runtime_result(
            raw_payload,
            returncode=run_result.returncode,
        )

    normalized_result = dict(raw_payload)
    normalized_result["scenario"] = str(compiled_record["scenario_id"])

    payload: dict[str, Any] = {
        "schema_version": EXECUTION_EVIDENCE_SCHEMA,
        "source_repository": ROUTER_CONFIGURATION_REPOSITORY,
        "router_configuration_sha": _require_sha40(
            binding.router_configuration_sha, "router_configuration_sha"
        ),
        "compiled_record_sha256": str(compiled_record["compiled_record_sha256"]),
        "scenario_id": str(compiled_record["scenario_id"]),
        "scenario_sha256": expected_scenario_sha256,
        "scenario_file_sha256": scenario_file_sha256,
        "network_sandbox_repository": NETWORK_SANDBOX_REPOSITORY,
        "network_sandbox_sha": _require_sha40(
            binding.network_sandbox_sha, "network_sandbox_sha"
        ),
        "network_sandbox_release": sandbox_version,
        "runtime_entrypoint": "python -m network_sandbox.cli",
        "runtime_source_verified": True,
        "validation_sha256": _canonical_sha256(validation_payload),
        "run_stdout_sha256": _bytes_sha256(
            str(run_result.stdout or "").encode("utf-8")
        ),
        "result_sha256": _canonical_sha256(normalized_result),
        "snapshot_sha256": _canonical_sha256(snapshot),
        "scenario_pass": scenario_pass,
        "summary": dict(summary),
        "result": normalized_result,
        "evidence_class_ceiling": EvidenceClass.VIRTUAL_VERIFIED.name,
        "hardware_present": False,
        "hardware_verified": False,
        "physical_device_verified": False,
        "production_write_authorized": False,
        "production_writer_available": False,
    }
    payload["execution_evidence_sha256"] = _canonical_sha256(payload)
    return NetworkSandboxExecutionEvidence(payload)
