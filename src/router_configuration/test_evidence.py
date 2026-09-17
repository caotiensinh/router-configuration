from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass
from typing import Any, Mapping, Sequence

_SHA1 = re.compile(r"^[0-9a-f]{40}$")
_RESULTS = frozenset({"PASS", "FAIL", "BLOCKED", "DEFERRED_EXTERNAL_HARDWARE"})
_SECRET_MARKERS = ("password=", "token=", "secret=", "private_key", "preshared_key", "psk=")


class TestEvidenceError(ValueError):
    pass


def _safe_text(value: Any, label: str) -> str:
    text = str(value or "").strip()
    if not text or any(c in text for c in ("\n", "\r", "\x00")):
        raise TestEvidenceError(f"{label} must be a non-empty safe value")
    if any(marker in text.lower() for marker in _SECRET_MARKERS):
        raise TestEvidenceError(f"{label} contains forbidden secret material")
    return text


def _items(values: Sequence[Any], label: str, *, allow_empty: bool = False) -> list[str]:
    items = [_safe_text(v, label) for v in values]
    if not allow_empty and not items:
        raise TestEvidenceError(f"{label} must not be empty")
    if len(items) != len(set(items)):
        raise TestEvidenceError(f"{label} must be unique")
    return sorted(items)


def _digest(payload: Mapping[str, Any]) -> str:
    raw = json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
    return hashlib.sha256(raw).hexdigest()


@dataclass(frozen=True)
class TestEvidence:
    payload: Mapping[str, Any]

    def as_dict(self) -> dict[str, Any]:
        return dict(self.payload)


def build_test_evidence(
    *,
    source_main_sha: str,
    test_scope: str,
    runner_identity: str,
    runtime_version: str,
    test_command: str,
    discovered_tests: Sequence[str],
    passed_tests: Sequence[str],
    failed_tests: Sequence[str],
    result: str,
    evidence_refs: Sequence[str],
    hardware_claim: bool = False,
    physical_evidence_refs: Sequence[str] = (),
) -> TestEvidence:
    sha = str(source_main_sha or "").strip().lower()
    if not _SHA1.fullmatch(sha):
        raise TestEvidenceError("source_main_sha must be a lowercase SHA-1")

    scope = _safe_text(test_scope, "test_scope")
    runner = _safe_text(runner_identity, "runner_identity")
    runtime = _safe_text(runtime_version, "runtime_version")
    command = _safe_text(test_command, "test_command")
    discovered = _items(discovered_tests, "discovered_tests", allow_empty=True)
    passed = _items(passed_tests, "passed_tests", allow_empty=True)
    failed = _items(failed_tests, "failed_tests", allow_empty=True)
    refs = _items(evidence_refs, "evidence_refs")
    physical_refs = _items(physical_evidence_refs, "physical_evidence_refs", allow_empty=True)

    if set(passed) & set(failed):
        raise TestEvidenceError("a test cannot be both passed and failed")
    if not set(passed).issubset(set(discovered)) or not set(failed).issubset(set(discovered)):
        raise TestEvidenceError("passed/failed tests must be discovered tests")

    state = str(result or "").strip().upper()
    if state not in _RESULTS:
        raise TestEvidenceError("unsupported result")
    if state == "PASS":
        if not discovered:
            raise TestEvidenceError("PASS requires actual test discovery")
        if failed:
            raise TestEvidenceError("PASS requires zero failed tests")
        if set(passed) != set(discovered):
            raise TestEvidenceError("PASS requires every discovered test to pass")
    if state == "FAIL" and not failed:
        raise TestEvidenceError("FAIL requires at least one failed test")
    if hardware_claim and not physical_refs:
        raise TestEvidenceError("hardware claim requires physical evidence")

    payload: dict[str, Any] = {
        "schema_version": "omada-test-evidence/1",
        "source_main_sha": sha,
        "test_scope": scope,
        "runner_identity": runner,
        "runtime_version": runtime,
        "test_command": command,
        "discovered_tests": discovered,
        "passed_tests": passed,
        "failed_tests": failed,
        "discovered_test_count": len(discovered),
        "passed_test_count": len(passed),
        "failed_test_count": len(failed),
        "result": state,
        "evidence_refs": refs,
        "hardware_claim": bool(hardware_claim),
        "physical_evidence_refs": physical_refs,
        "generic_ci_green_is_sufficient": False,
        "transport_present": False,
        "apply_available": False,
        "production_write_authority": False,
    }
    payload["test_evidence_sha256"] = _digest(payload)
    return TestEvidence(payload)
