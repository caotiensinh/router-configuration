from __future__ import annotations

import hashlib
import hmac
import json
import re
from dataclasses import dataclass
from typing import Any, Mapping, Sequence

from .transaction_backup_evidence import (
    TransactionBackupEvidenceError,
    validate_transaction_backup_evidence,
)
from .transaction_lifecycle import (
    TransactionLifecycleError,
    _verify_envelope,
    _verify_lifecycle,
)


class ProductionTransactionReadinessError(ValueError):
    pass


_SHA256 = re.compile(r"^[0-9a-f]{64}$")
_REQUIRED_BACKUP_KINDS = frozenset({"sanitized_export", "protected_ephemeral_binary"})
_BASE_VERIFICATION_CHECKS = frozenset({"management", "wan", "dns", "routing"})
_FORBIDDEN_RUNTIME_FIELDS = frozenset(
    {
        "url",
        "router_url",
        "username",
        "password",
        "credential",
        "credential_ref",
        "token",
        "secret",
        "private_key",
        "transport",
        "method",
        "shell",
        "command",
        "commands",
    }
)


def _canonical_sha256(value: Any) -> str:
    encoded = json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        default=str,
    ).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def _digest(value: Any, label: str) -> str:
    text = str(value or "").strip().lower()
    if not _SHA256.fullmatch(text):
        raise ProductionTransactionReadinessError(
            f"{label} must be a lowercase SHA-256 digest"
        )
    return text


def _reference(value: Any, label: str) -> str:
    text = str(value or "").strip()
    if not text:
        raise ProductionTransactionReadinessError(f"{label} must not be empty")
    if any(character in text for character in ("\n", "\r", "\x00")):
        raise ProductionTransactionReadinessError(
            f"{label} contains unsupported control characters"
        )
    return text


def _assert_no_runtime_capability(value: Mapping[str, Any], label: str) -> None:
    present = sorted(
        str(key)
        for key in value
        if str(key).lower() in _FORBIDDEN_RUNTIME_FIELDS
    )
    if present:
        raise ProductionTransactionReadinessError(
            f"{label} contains runtime-capability fields: {', '.join(present)}"
        )


def _required_verification_checks(profile: Mapping[str, Any]) -> tuple[str, ...]:
    required = set(_BASE_VERIFICATION_CHECKS)
    intent = profile.get("intent", {})
    if isinstance(intent, Mapping):
        vpn = intent.get("vpn")
        if isinstance(vpn, Mapping):
            wireguard = vpn.get("wireguard")
            if isinstance(wireguard, Mapping) and wireguard.get("enabled") is True:
                required.add("vpn")
    return tuple(sorted(required))


def _verify_management_guard(evidence: Mapping[str, Any]) -> str:
    if evidence.get("schema_version") != "routeros-production-management-readiness/1":
        raise ProductionTransactionReadinessError(
            "unsupported production management readiness schema"
        )
    _assert_no_runtime_capability(evidence, "management readiness evidence")
    required_true = (
        "pre_change_reachable",
        "independent_probe",
        "monitor_during_apply",
        "post_apply_verification_required",
        "rollback_recovery_verification_required",
    )
    missing = [field for field in required_true if evidence.get(field) is not True]
    if missing:
        raise ProductionTransactionReadinessError(
            "management readiness is incomplete: " + ", ".join(missing)
        )
    return _reference(evidence.get("evidence_ref"), "management.evidence_ref")


def _verify_verification_contract(
    contract: Mapping[str, Any],
    *,
    required_checks: Sequence[str],
) -> dict[str, str]:
    if contract.get("schema_version") != "routeros-production-verification-contract/1":
        raise ProductionTransactionReadinessError(
            "unsupported production verification contract schema"
        )
    _assert_no_runtime_capability(contract, "verification contract")
    if contract.get("stop_on_failure") is not True:
        raise ProductionTransactionReadinessError(
            "verification contract must stop on failure"
        )
    checks = contract.get("checks")
    if not isinstance(checks, Mapping):
        raise ProductionTransactionReadinessError(
            "verification contract checks must be an object"
        )

    normalized: dict[str, str] = {}
    for name in required_checks:
        item = checks.get(name)
        if not isinstance(item, Mapping):
            raise ProductionTransactionReadinessError(
                f"verification contract is missing required check: {name}"
            )
        _assert_no_runtime_capability(item, f"verification check {name}")
        required_true = (
            "required",
            "readback_required",
            "behavior_verification_required",
        )
        missing = [field for field in required_true if item.get(field) is not True]
        if missing:
            raise ProductionTransactionReadinessError(
                f"verification check {name} is incomplete: {', '.join(missing)}"
            )
        normalized[name] = _reference(
            item.get("evidence_ref"), f"verification.{name}.evidence_ref"
        )
    return normalized


def _verify_rollback_contract(contract: Mapping[str, Any]) -> str:
    if contract.get("schema_version") != "routeros-production-rollback-contract/1":
        raise ProductionTransactionReadinessError(
            "unsupported production rollback contract schema"
        )
    _assert_no_runtime_capability(contract, "rollback contract")
    required_true = (
        "stop_further_changes",
        "assess_state",
        "rollback_required_on_verification_failure",
        "verify_restored_state",
        "incident_evidence_required",
    )
    missing = [field for field in required_true if contract.get(field) is not True]
    if missing:
        raise ProductionTransactionReadinessError(
            "rollback contract is incomplete: " + ", ".join(missing)
        )
    return _reference(contract.get("strategy_ref"), "rollback.strategy_ref")


def _verify_dual_backups(
    backups: Sequence[Mapping[str, Any]],
    *,
    expected_pre_state_sha256: str,
    envelope_backup_evidence_sha256: str,
) -> dict[str, Mapping[str, Any]]:
    if len(backups) != 2:
        raise ProductionTransactionReadinessError(
            "production readiness requires exactly two pre-change backup evidence records"
        )

    by_kind: dict[str, Mapping[str, Any]] = {}
    observed_evidence_digests: set[str] = set()
    for evidence in backups:
        if not isinstance(evidence, Mapping):
            raise ProductionTransactionReadinessError(
                "backup evidence entries must be objects"
            )
        try:
            validate_transaction_backup_evidence(
                evidence,
                expected_pre_state_sha256=expected_pre_state_sha256,
            )
        except TransactionBackupEvidenceError as exc:
            raise ProductionTransactionReadinessError(
                "production backup evidence verification failed"
            ) from exc
        kind = str(evidence.get("kind") or "")
        if kind in by_kind:
            raise ProductionTransactionReadinessError(
                f"duplicate production backup evidence kind: {kind}"
            )
        by_kind[kind] = dict(evidence)
        observed_evidence_digests.add(
            _digest(evidence.get("evidence_sha256"), "backup.evidence_sha256")
        )

    if set(by_kind) != set(_REQUIRED_BACKUP_KINDS):
        raise ProductionTransactionReadinessError(
            "production readiness requires sanitized_export and protected_ephemeral_binary backups"
        )
    if envelope_backup_evidence_sha256 not in observed_evidence_digests:
        raise ProductionTransactionReadinessError(
            "transaction envelope backup is not present in the dual-backup set"
        )
    return by_kind


@dataclass(frozen=True)
class ProductionTransactionReadiness:
    payload: Mapping[str, Any]

    def as_dict(self) -> dict[str, Any]:
        return dict(self.payload)


def build_production_transaction_readiness(
    *,
    profile: Mapping[str, Any],
    envelope: Mapping[str, Any],
    lifecycle: Mapping[str, Any],
    backups: Sequence[Mapping[str, Any]],
    management_path: Mapping[str, Any],
    verification_contract: Mapping[str, Any],
    rollback_contract: Mapping[str, Any],
) -> ProductionTransactionReadiness:
    """Verify production prerequisites without exposing execution capability."""

    try:
        transaction_id, envelope_sha, pre_state_sha = _verify_envelope(envelope)
        _verify_lifecycle(lifecycle)
    except TransactionLifecycleError as exc:
        raise ProductionTransactionReadinessError(
            "transaction envelope/lifecycle verification failed"
        ) from exc

    if lifecycle.get("phase") != "authorized":
        raise ProductionTransactionReadinessError(
            "production readiness requires lifecycle phase authorized"
        )
    if not hmac.compare_digest(
        str(lifecycle.get("transaction_id") or ""), transaction_id
    ):
        raise ProductionTransactionReadinessError(
            "lifecycle is bound to a different transaction"
        )
    if not hmac.compare_digest(
        str(lifecycle.get("envelope_sha256") or ""), envelope_sha
    ):
        raise ProductionTransactionReadinessError(
            "lifecycle is bound to a different envelope"
        )

    bindings = envelope.get("bindings")
    if not isinstance(bindings, Mapping):
        raise ProductionTransactionReadinessError(
            "transaction envelope bindings are missing"
        )
    envelope_backup = bindings.get("backup")
    if not isinstance(envelope_backup, Mapping):
        raise ProductionTransactionReadinessError(
            "transaction envelope backup binding is missing"
        )
    envelope_backup_digest = _digest(
        envelope_backup.get("evidence_sha256"),
        "envelope.backup.evidence_sha256",
    )
    verified_backups = _verify_dual_backups(
        backups,
        expected_pre_state_sha256=pre_state_sha,
        envelope_backup_evidence_sha256=envelope_backup_digest,
    )

    management_ref = _verify_management_guard(management_path)
    required_checks = _required_verification_checks(profile)
    verification_refs = _verify_verification_contract(
        verification_contract,
        required_checks=required_checks,
    )
    rollback_ref = _verify_rollback_contract(rollback_contract)

    payload: dict[str, Any] = {
        "schema_version": "routeros-production-transaction-readiness/1",
        "claim": "production_requirements_complete_execution_still_disabled",
        "ready": True,
        "transaction_id": transaction_id,
        "envelope_sha256": envelope_sha,
        "pre_state_sha256": pre_state_sha,
        "backup_kinds": sorted(verified_backups),
        "backup_evidence_sha256": {
            kind: str(item.get("evidence_sha256") or "")
            for kind, item in sorted(verified_backups.items())
        },
        "management_evidence_ref": management_ref,
        "required_verification_checks": list(required_checks),
        "verification_evidence_refs": dict(sorted(verification_refs.items())),
        "rollback_strategy_ref": rollback_ref,
        "secrets_present": False,
        "transport_present": False,
        "apply_available": False,
        "production_writer_available": False,
        "write_authorized": False,
    }
    payload["readiness_sha256"] = _canonical_sha256(payload)
    return ProductionTransactionReadiness(payload)


def _verify_readiness(readiness: Mapping[str, Any]) -> tuple[str, str]:
    if readiness.get("schema_version") != "routeros-production-transaction-readiness/1":
        raise ProductionTransactionReadinessError(
            "unsupported production transaction readiness schema"
        )
    if readiness.get("ready") is not True:
        raise ProductionTransactionReadinessError(
            "production transaction readiness must report ready=true"
        )
    for field in (
        "secrets_present",
        "transport_present",
        "apply_available",
        "production_writer_available",
        "write_authorized",
    ):
        if readiness.get(field) is not False:
            raise ProductionTransactionReadinessError(
                f"production readiness must keep {field}=false"
            )
    supplied = _digest(readiness.get("readiness_sha256"), "readiness_sha256")
    unsigned = dict(readiness)
    unsigned.pop("readiness_sha256", None)
    if not hmac.compare_digest(supplied, _canonical_sha256(unsigned)):
        raise ProductionTransactionReadinessError(
            "production transaction readiness digest mismatch"
        )
    transaction_id = _digest(readiness.get("transaction_id"), "transaction_id")
    pre_state_sha = _digest(readiness.get("pre_state_sha256"), "pre_state_sha256")
    return transaction_id, pre_state_sha


def evaluate_production_verification_outcome(
    *,
    readiness: Mapping[str, Any],
    lifecycle: Mapping[str, Any],
    verification_evidence: Mapping[str, Any],
) -> dict[str, Any]:
    """Evaluate verified success or verified rollback recovery evidence only."""

    transaction_id, pre_state_sha = _verify_readiness(readiness)
    try:
        _verify_lifecycle(lifecycle)
    except TransactionLifecycleError as exc:
        raise ProductionTransactionReadinessError(
            "transaction lifecycle verification failed"
        ) from exc
    if not hmac.compare_digest(
        str(lifecycle.get("transaction_id") or ""), transaction_id
    ):
        raise ProductionTransactionReadinessError(
            "outcome lifecycle is bound to a different transaction"
        )

    if verification_evidence.get("schema_version") != "routeros-production-verification-evidence/1":
        raise ProductionTransactionReadinessError(
            "unsupported production verification evidence schema"
        )
    _assert_no_runtime_capability(
        verification_evidence, "production verification evidence"
    )
    checks = verification_evidence.get("checks")
    if not isinstance(checks, Mapping):
        raise ProductionTransactionReadinessError(
            "production verification evidence checks must be an object"
        )
    required = readiness.get("required_verification_checks")
    if not isinstance(required, list) or not required:
        raise ProductionTransactionReadinessError(
            "production readiness required_verification_checks is invalid"
        )

    phase = str(lifecycle.get("phase") or "")
    normalized_checks: dict[str, dict[str, Any]] = {}
    for name in required:
        key = str(name)
        item = checks.get(key)
        if not isinstance(item, Mapping):
            raise ProductionTransactionReadinessError(
                f"verification evidence is missing required check: {key}"
            )
        _assert_no_runtime_capability(item, f"verification evidence check {key}")
        normalized_checks[key] = {
            "ok": item.get("ok") is True,
            "evidence_ref": _reference(
                item.get("evidence_ref"), f"verification evidence {key}.evidence_ref"
            ),
        }

    deployment_success = False
    failure_recovered = False
    rollback_evidence_ref: str | None = None

    if phase == "verified":
        failed = sorted(name for name, item in normalized_checks.items() if not item["ok"])
        if failed:
            raise ProductionTransactionReadinessError(
                "verified lifecycle contains failed verification checks: "
                + ", ".join(failed)
            )
        deployment_success = True
        outcome = "verified_success"
    elif phase == "rolled_back":
        if verification_evidence.get("failure_observed") is not True:
            raise ProductionTransactionReadinessError(
                "rolled_back outcome requires failure_observed=true"
            )
        recovery = verification_evidence.get("recovery")
        if not isinstance(recovery, Mapping):
            raise ProductionTransactionReadinessError(
                "rolled_back outcome requires recovery evidence"
            )
        _assert_no_runtime_capability(recovery, "recovery evidence")
        for field in (
            "management_recovered",
            "connectivity_recovered",
            "managed_objects_reconciled",
        ):
            if recovery.get(field) is not True:
                raise ProductionTransactionReadinessError(
                    f"rolled_back recovery requires {field}=true"
                )
        rollback_state_sha = _digest(
            recovery.get("rollback_state_sha256"),
            "recovery.rollback_state_sha256",
        )
        if not hmac.compare_digest(rollback_state_sha, pre_state_sha):
            raise ProductionTransactionReadinessError(
                "rollback recovery state does not match the bound pre-state digest"
            )
        rollback_evidence_ref = _reference(
            recovery.get("evidence_ref"), "recovery.evidence_ref"
        )
        failure_recovered = True
        outcome = "failure_recovered"
    else:
        raise ProductionTransactionReadinessError(
            "production outcome requires terminal lifecycle phase verified or rolled_back"
        )

    result: dict[str, Any] = {
        "schema_version": "routeros-production-verification-outcome/1",
        "transaction_id": transaction_id,
        "outcome": outcome,
        "deployment_success": deployment_success,
        "failure_recovered": failure_recovered,
        "checks": normalized_checks,
        "rollback_evidence_ref": rollback_evidence_ref,
        "secrets_present": False,
        "transport_present": False,
        "apply_available": False,
        "production_writer_available": False,
        "write_authorized": False,
    }
    result["outcome_sha256"] = _canonical_sha256(result)
    return result
