from __future__ import annotations

import hashlib
import hmac
import json
from dataclasses import dataclass
from datetime import datetime
from typing import Any, Mapping

from .routeros_capabilities import assess_routeros_capabilities

_STATE_KEYS = {
    "schema_version",
    "platform",
    "interfaces",
    "ip_addresses",
    "ip_routes",
    "routing_tables",
    "firewall",
    "wireguard",
    "qos",
    "missing_surfaces",
}

_SECRET_KEY_TOKENS = (
    "password",
    "private-key",
    "private_key",
    "preshared-key",
    "preshared_key",
    "psk",
    "secret",
    "token",
)


@dataclass(frozen=True)
class StateValidationResult:
    errors: tuple[str, ...]
    warnings: tuple[str, ...] = ()

    @property
    def ok(self) -> bool:
        return not self.errors


@dataclass(frozen=True)
class EvidenceVerificationResult:
    errors: tuple[str, ...]
    warnings: tuple[str, ...]
    state: Mapping[str, Any] | None

    @property
    def ok(self) -> bool:
        return not self.errors

    def as_dict(self) -> dict[str, Any]:
        return {
            "ok": self.ok,
            "errors": list(self.errors),
            "warnings": list(self.warnings),
            "state_schema": (
                self.state.get("schema_version")
                if isinstance(self.state, Mapping)
                else None
            ),
        }


def routeros_state_digest(state: Mapping[str, Any]) -> str:
    payload = json.dumps(
        state,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        default=str,
    ).encode("utf-8")
    return hashlib.sha256(payload).hexdigest()


def _contains_unredacted_secret(value: Any, path: str = "$") -> list[str]:
    findings: list[str] = []
    if isinstance(value, Mapping):
        for key, item in value.items():
            key_text = str(key)
            child_path = f"{path}.{key_text}"
            lowered = key_text.lower()
            if any(token in lowered for token in _SECRET_KEY_TOKENS):
                if item != "<redacted>":
                    findings.append(child_path)
            findings.extend(_contains_unredacted_secret(item, child_path))
    elif isinstance(value, list):
        for index, item in enumerate(value):
            findings.extend(_contains_unredacted_secret(item, f"{path}[{index}]"))
    return findings


def _validate_record_list(value: Any, path: str, errors: list[str]) -> None:
    if not isinstance(value, list):
        errors.append(f"{path} must be a list")
        return
    for index, item in enumerate(value):
        if not isinstance(item, Mapping):
            errors.append(f"{path}[{index}] must be an object")


def validate_routeros_state(state: Mapping[str, Any]) -> StateValidationResult:
    errors: list[str] = []
    warnings: list[str] = []

    unknown = sorted(set(state) - _STATE_KEYS)
    missing = sorted(_STATE_KEYS - set(state))
    if unknown:
        errors.append("unknown top-level state fields: " + ", ".join(unknown))
    if missing:
        errors.append("missing top-level state fields: " + ", ".join(missing))

    if state.get("schema_version") != "routeros-state/1":
        errors.append("schema_version must be routeros-state/1")

    platform = state.get("platform")
    if not isinstance(platform, Mapping):
        errors.append("platform must be an object")
    else:
        expected_platform = {"identity", "version", "board_name", "architecture"}
        unknown_platform = sorted(set(platform) - expected_platform)
        if unknown_platform:
            errors.append("unknown platform fields: " + ", ".join(unknown_platform))
        for key in expected_platform:
            value = platform.get(key)
            if value is not None and not isinstance(value, str):
                errors.append(f"platform.{key} must be a string or null")
        if not platform.get("identity"):
            warnings.append("platform.identity is empty")
        if not platform.get("version"):
            warnings.append("platform.version is empty")
        if not platform.get("board_name"):
            warnings.append("platform.board_name is empty")

    for name in ("interfaces", "ip_addresses", "ip_routes", "routing_tables"):
        _validate_record_list(state.get(name), name, errors)

    firewall = state.get("firewall")
    if not isinstance(firewall, Mapping):
        errors.append("firewall must be an object")
    else:
        if set(firewall) - {"filter", "nat"}:
            errors.append("firewall contains unsupported fields")
        _validate_record_list(firewall.get("filter"), "firewall.filter", errors)
        _validate_record_list(firewall.get("nat"), "firewall.nat", errors)

    wireguard = state.get("wireguard")
    if not isinstance(wireguard, Mapping):
        errors.append("wireguard must be an object")
    else:
        if set(wireguard) - {"interfaces", "peers"}:
            errors.append("wireguard contains unsupported fields")
        _validate_record_list(
            wireguard.get("interfaces"), "wireguard.interfaces", errors
        )
        _validate_record_list(wireguard.get("peers"), "wireguard.peers", errors)

    qos = state.get("qos")
    if not isinstance(qos, Mapping):
        errors.append("qos must be an object")
    else:
        if set(qos) - {"simple_queues", "queue_tree"}:
            errors.append("qos contains unsupported fields")
        _validate_record_list(qos.get("simple_queues"), "qos.simple_queues", errors)
        _validate_record_list(qos.get("queue_tree"), "qos.queue_tree", errors)

    missing_surfaces = state.get("missing_surfaces")
    if not isinstance(missing_surfaces, list) or not all(
        isinstance(item, str) for item in missing_surfaces
    ):
        errors.append("missing_surfaces must be a list of strings")
    elif missing_surfaces != sorted(set(missing_surfaces)):
        errors.append("missing_surfaces must be sorted and unique")

    secret_paths = _contains_unredacted_secret(state)
    if secret_paths:
        errors.append(
            "unredacted secret-bearing state fields: " + ", ".join(secret_paths)
        )

    return StateValidationResult(tuple(errors), tuple(warnings))


def _record_counts(state: Mapping[str, Any]) -> dict[str, int]:
    firewall = state.get("firewall", {})
    wireguard = state.get("wireguard", {})
    qos = state.get("qos", {})
    return {
        "interfaces": len(state.get("interfaces", [])),
        "ip_addresses": len(state.get("ip_addresses", [])),
        "ip_routes": len(state.get("ip_routes", [])),
        "routing_tables": len(state.get("routing_tables", [])),
        "firewall_filter": len(firewall.get("filter", [])),
        "firewall_nat": len(firewall.get("nat", [])),
        "wireguard_interfaces": len(wireguard.get("interfaces", [])),
        "wireguard_peers": len(wireguard.get("peers", [])),
        "qos_simple_queues": len(qos.get("simple_queues", [])),
        "qos_queue_tree": len(qos.get("queue_tree", [])),
    }


def verify_routeros_discovery_evidence(
    evidence: Mapping[str, Any],
) -> EvidenceVerificationResult:
    errors: list[str] = []
    warnings: list[str] = []

    if evidence.get("schema_version") != "routeros-discovery-evidence/1":
        errors.append("schema_version must be routeros-discovery-evidence/1")

    state = evidence.get("normalized_state")
    if not isinstance(state, Mapping):
        errors.append("normalized_state must be an object")
        return EvidenceVerificationResult(tuple(errors), tuple(warnings), None)

    state_validation = validate_routeros_state(state)
    errors.extend(state_validation.errors)
    warnings.extend(state_validation.warnings)

    expected_digest = routeros_state_digest(state)
    actual_digest = evidence.get("state_sha256")
    if not isinstance(actual_digest, str) or not hmac.compare_digest(
        actual_digest, expected_digest
    ):
        errors.append("state_sha256 does not match normalized_state")

    if evidence.get("platform") != state.get("platform"):
        errors.append("evidence platform does not match normalized_state.platform")

    observed_at = evidence.get("observed_at")
    if not isinstance(observed_at, str):
        errors.append("observed_at must be an ISO-8601 string")
    else:
        try:
            parsed = datetime.fromisoformat(observed_at.replace("Z", "+00:00"))
            if parsed.tzinfo is None:
                raise ValueError
        except ValueError:
            errors.append("observed_at must include a timezone")

    collection = evidence.get("collection")
    if not isinstance(collection, Mapping):
        errors.append("collection must be an object")
    else:
        failed = collection.get("failed_surfaces")
        surface_errors = collection.get("surface_errors")
        if not isinstance(failed, list) or not all(
            isinstance(item, str) for item in failed
        ):
            errors.append("collection.failed_surfaces must be a list of strings")
        elif failed != sorted(set(failed)):
            errors.append("collection.failed_surfaces must be sorted and unique")

        if not isinstance(surface_errors, Mapping):
            errors.append("collection.surface_errors must be an object")
        elif isinstance(failed, list) and set(surface_errors) != set(failed):
            errors.append(
                "collection.surface_errors keys must equal failed_surfaces"
            )

        if collection.get("missing_surfaces") != state.get("missing_surfaces"):
            errors.append(
                "collection.missing_surfaces does not match normalized_state"
            )

        if collection.get("record_counts") != _record_counts(state):
            errors.append("collection.record_counts does not match normalized_state")

    expected_capabilities = assess_routeros_capabilities(state).as_dict()
    if evidence.get("capabilities") != expected_capabilities:
        errors.append("capabilities do not match normalized_state assessment")

    return EvidenceVerificationResult(tuple(errors), tuple(warnings), state)
