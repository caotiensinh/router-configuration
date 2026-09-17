"""Fail-closed Yamaha RTX3510 read-only command admission and evidence contracts."""

from __future__ import annotations

from dataclasses import dataclass
import hashlib
import json
import re
from typing import Mapping

from .knowledge import YamahaOfflineKnowledge
from .platforms import assess_read_only_candidate


class YamahaReadOnlyEvidenceError(ValueError):
    """Raised when Yamaha read-only evidence violates the bounded contract."""


@dataclass(frozen=True)
class YamahaReadOnlyCommandDecision:
    status: str
    input_command: str
    normalized_command: str
    query_id: str | None
    allowed: bool
    mutation: bool = False


@dataclass(frozen=True)
class YamahaEnvironmentIdentity:
    model: str
    firmware: str
    read_only_candidate: bool
    write_authorized: bool = False
    physical_device_verified: bool = False


_REQUIRED_DISCOVERY_COMMANDS = frozenset(
    {
        "show environment",
        "show ip route",
        "show status lan1",
        "show status lan2",
        "show status lan3",
        "show status lan4",
    }
)
_MODEL_RE = re.compile(r"\bRTX3510\b", re.IGNORECASE)
_FIRMWARE_RE = re.compile(r"\bRev\.(\d{2}\.\d{2}\.\d{2})\b", re.IGNORECASE)


def normalize_read_only_command(command: str) -> str:
    if not isinstance(command, str):
        raise TypeError("command must be a string")
    return " ".join(command.strip().split())


def validate_read_only_command(command: str) -> YamahaReadOnlyCommandDecision:
    normalized = normalize_read_only_command(command)
    if not normalized:
        return YamahaReadOnlyCommandDecision(
            status="BLOCKED_EMPTY_COMMAND",
            input_command=command,
            normalized_command=normalized,
            query_id=None,
            allowed=False,
        )

    catalog = YamahaOfflineKnowledge().readonly_catalog
    for query in catalog["queries"]:
        if normalized == query["command"]:
            return YamahaReadOnlyCommandDecision(
                status="ALLOWED_READ_ONLY_COMMAND",
                input_command=command,
                normalized_command=normalized,
                query_id=query["id"],
                allowed=True,
            )

    return YamahaReadOnlyCommandDecision(
        status="BLOCKED_UNVERIFIED_COMMAND",
        input_command=command,
        normalized_command=normalized,
        query_id=None,
        allowed=False,
    )


def parse_environment_identity(output: str) -> YamahaEnvironmentIdentity:
    if not isinstance(output, str) or not output.strip():
        raise YamahaReadOnlyEvidenceError("show environment output is empty")

    model_match = _MODEL_RE.search(output)
    firmware_match = _FIRMWARE_RE.search(output)
    if model_match is None:
        raise YamahaReadOnlyEvidenceError("RTX3510 identity was not observed")
    if firmware_match is None:
        raise YamahaReadOnlyEvidenceError("firmware revision was not observed")

    firmware = firmware_match.group(1)
    decision = assess_read_only_candidate("RTX3510", firmware)
    if not decision.read_only_candidate:
        raise YamahaReadOnlyEvidenceError(
            f"observed Yamaha firmware is not admitted: {firmware}"
        )

    return YamahaEnvironmentIdentity(
        model="RTX3510",
        firmware=firmware,
        read_only_candidate=True,
    )


def build_readonly_evidence(outputs: Mapping[str, str]) -> dict:
    """Build digest-bound caller-supplied evidence without claiming live hardware.

    The caller supplies outputs captured elsewhere. This function proves that the
    requested commands are within the validated read-only catalog and that the
    observed identity matches the admitted RTX3510 firmware. It does not prove
    transport authenticity, least-privilege enforcement, or physical hardware.
    """

    if not isinstance(outputs, Mapping) or not outputs:
        raise YamahaReadOnlyEvidenceError("read-only outputs must be a non-empty mapping")

    canonical_outputs: dict[str, str] = {}
    query_ids: dict[str, str] = {}
    for command, output in outputs.items():
        decision = validate_read_only_command(command)
        if not decision.allowed or decision.query_id is None:
            raise YamahaReadOnlyEvidenceError(
                f"unverified Yamaha command in evidence: {decision.normalized_command}"
            )
        if not isinstance(output, str) or not output.strip():
            raise YamahaReadOnlyEvidenceError(
                f"empty Yamaha output: {decision.normalized_command}"
            )
        if decision.normalized_command in canonical_outputs:
            raise YamahaReadOnlyEvidenceError(
                f"duplicate normalized Yamaha command: {decision.normalized_command}"
            )
        canonical_outputs[decision.normalized_command] = output
        query_ids[decision.normalized_command] = decision.query_id

    missing = sorted(_REQUIRED_DISCOVERY_COMMANDS.difference(canonical_outputs))
    if missing:
        raise YamahaReadOnlyEvidenceError(
            "missing required Yamaha discovery commands: " + ", ".join(missing)
        )

    identity = parse_environment_identity(canonical_outputs["show environment"])
    command_records = []
    for command in sorted(canonical_outputs):
        payload = canonical_outputs[command].encode("utf-8")
        command_records.append(
            {
                "query_id": query_ids[command],
                "command": command,
                "output_sha256": hashlib.sha256(payload).hexdigest(),
                "output_bytes": len(payload),
            }
        )

    record = {
        "schema_version": "yamaha-rtx3510-readonly-evidence/1",
        "vendor": "Yamaha",
        "model": identity.model,
        "firmware": identity.firmware,
        "capture_source": "caller_supplied",
        "commands": command_records,
        "raw_outputs_embedded": False,
        "transport_verified": False,
        "least_privilege_verified": False,
        "live_device_verified": False,
        "physical_device_verified": False,
        "production_write_authorized": False,
    }
    canonical = json.dumps(record, sort_keys=True, separators=(",", ":"))
    record["record_sha256"] = hashlib.sha256(canonical.encode("utf-8")).hexdigest()
    return record


def validate_readonly_evidence(record: Mapping[str, object]) -> None:
    if record.get("schema_version") != "yamaha-rtx3510-readonly-evidence/1":
        raise YamahaReadOnlyEvidenceError("unsupported Yamaha read-only evidence schema")
    if record.get("vendor") != "Yamaha" or record.get("model") != "RTX3510":
        raise YamahaReadOnlyEvidenceError("Yamaha read-only evidence identity mismatch")
    if record.get("firmware") != "23.01.03":
        raise YamahaReadOnlyEvidenceError("Yamaha evidence firmware is not admitted")
    for key in (
        "transport_verified",
        "least_privilege_verified",
        "live_device_verified",
        "physical_device_verified",
        "production_write_authorized",
    ):
        if record.get(key) is not False:
            raise YamahaReadOnlyEvidenceError(f"Yamaha evidence overclaims {key}")
    if record.get("raw_outputs_embedded") is not False:
        raise YamahaReadOnlyEvidenceError("raw Yamaha outputs must not be embedded")

    commands = record.get("commands")
    if not isinstance(commands, list) or not commands:
        raise YamahaReadOnlyEvidenceError("Yamaha evidence commands are missing")
    observed: set[str] = set()
    for item in commands:
        if not isinstance(item, dict):
            raise YamahaReadOnlyEvidenceError("invalid Yamaha command evidence entry")
        command = item.get("command")
        if not isinstance(command, str) or not validate_read_only_command(command).allowed:
            raise YamahaReadOnlyEvidenceError("evidence contains unverified Yamaha command")
        observed.add(command)
        digest = item.get("output_sha256")
        if not isinstance(digest, str) or re.fullmatch(r"[0-9a-f]{64}", digest) is None:
            raise YamahaReadOnlyEvidenceError("invalid Yamaha output digest")
        if not isinstance(item.get("output_bytes"), int) or item["output_bytes"] <= 0:
            raise YamahaReadOnlyEvidenceError("invalid Yamaha output size")

    if not _REQUIRED_DISCOVERY_COMMANDS.issubset(observed):
        raise YamahaReadOnlyEvidenceError("Yamaha evidence is missing required discovery coverage")

    supplied_digest = record.get("record_sha256")
    if not isinstance(supplied_digest, str) or re.fullmatch(r"[0-9a-f]{64}", supplied_digest) is None:
        raise YamahaReadOnlyEvidenceError("invalid Yamaha record digest")
    payload = dict(record)
    payload.pop("record_sha256", None)
    canonical = json.dumps(payload, sort_keys=True, separators=(",", ":"))
    expected = hashlib.sha256(canonical.encode("utf-8")).hexdigest()
    if supplied_digest != expected:
        raise YamahaReadOnlyEvidenceError("Yamaha read-only evidence digest mismatch")
