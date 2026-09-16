from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass
from typing import Any, Mapping, Sequence

_SHA1 = re.compile(r"^[0-9a-f]{40}$")
_SHA256 = re.compile(r"^[0-9a-f]{64}$")
_FORBIDDEN_KEYS = frozenset({
    "password", "credential", "credentials", "credential_ref", "token", "access_token",
    "refresh_token", "client_secret", "secret", "shared_secret", "private_key",
    "preshared_key", "psk", "command", "commands", "shell", "transport", "writer",
})


class ConfigurationReportError(ValueError):
    pass


def _sha256(value: Any) -> str:
    return hashlib.sha256(
        json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False, default=str).encode("utf-8")
    ).hexdigest()


def _safe_strings(values: Sequence[Any], label: str) -> tuple[str, ...]:
    out = tuple(str(v).strip() for v in values)
    if not out or any(not item or any(c in item for c in ("\n", "\r", "\x00")) for item in out):
        raise ConfigurationReportError(f"{label} must contain non-empty safe values")
    if len(set(out)) != len(out):
        raise ConfigurationReportError(f"{label} must be unique")
    return out


def _reject_sensitive(value: Any, path: str = "configuration") -> None:
    if isinstance(value, Mapping):
        for key, child in value.items():
            name = str(key).strip().lower()
            if name in _FORBIDDEN_KEYS or any(
                marker in name for marker in ("password", "private_key", "client_secret", "access_token", "refresh_token")
            ):
                raise ConfigurationReportError(f"{path} contains forbidden secret/runtime field: {key}")
            _reject_sensitive(child, f"{path}.{key}")
    elif isinstance(value, (list, tuple)):
        for index, child in enumerate(value):
            _reject_sensitive(child, f"{path}[{index}]")


def _verify_final_validation(value: Mapping[str, Any]) -> tuple[str, str]:
    if not isinstance(value, Mapping):
        raise ConfigurationReportError("final_validation must be an object")
    if value.get("acceptance") != "PASS" or value.get("desired_matches_actual") is not True:
        raise ConfigurationReportError("configuration report requires PASS final desired-vs-actual validation")
    if value.get("fresh_read") is not True or value.get("independently_acquired") is not True:
        raise ConfigurationReportError("configuration report requires fresh independent final readback")
    digest = str(value.get("final_validation_sha256") or "").strip().lower()
    if not _SHA256.fullmatch(digest):
        raise ConfigurationReportError("final_validation_sha256 must be a lowercase SHA-256 digest")
    transaction_id = str(value.get("transaction_id") or "").strip().lower()
    if not _SHA256.fullmatch(transaction_id):
        raise ConfigurationReportError("transaction_id must be a lowercase SHA-256 digest")
    return transaction_id, digest


@dataclass(frozen=True)
class ConfigurationReport:
    payload: Mapping[str, Any]

    def as_dict(self) -> dict[str, Any]:
        return dict(self.payload)


def build_configuration_report(
    *,
    project_name: str,
    main_sha: str,
    final_validation: Mapping[str, Any],
    verified_configuration: Mapping[str, Any],
    scope: Sequence[str],
    evidence_refs: Sequence[str],
    deviations: Sequence[str] = (),
) -> ConfigurationReport:
    name = str(project_name or "").strip()
    if not name:
        raise ConfigurationReportError("project_name must not be empty")
    sha = str(main_sha or "").strip().lower()
    if not _SHA1.fullmatch(sha):
        raise ConfigurationReportError("main_sha must be a lowercase SHA-1 commit id")
    if not isinstance(verified_configuration, Mapping) or not verified_configuration:
        raise ConfigurationReportError("verified_configuration must be a non-empty object")

    transaction_id, validation_digest = _verify_final_validation(final_validation)
    _reject_sensitive(verified_configuration)
    scopes = _safe_strings(scope, "scope")
    refs = _safe_strings(evidence_refs, "evidence_refs")
    devs = tuple(str(v).strip() for v in deviations)
    if any(not item or "\x00" in item for item in devs):
        raise ConfigurationReportError("deviations contains an unsafe value")

    canonical_configuration = json.loads(
        json.dumps(verified_configuration, sort_keys=True, separators=(",", ":"), ensure_ascii=False, default=str)
    )
    payload = {
        "schema_version": "omada-configuration-report/1",
        "project_name": name,
        "current_main": sha,
        "transaction_id": transaction_id,
        "final_validation_sha256": validation_digest,
        "scope": list(scopes),
        "verified_configuration": canonical_configuration,
        "configuration_sha256": _sha256(canonical_configuration),
        "deviations": list(devs),
        "evidence_refs": list(refs),
        "claim": "verified_configuration_report_only",
        "fresh_independent_readback_required": True,
        "secret_material_included": False,
        "transport_present": False,
        "apply_available": False,
        "rollback_available": False,
        "production_writer_available": False,
        "write_authorized": False,
    }
    payload["configuration_report_sha256"] = _sha256(payload)
    return ConfigurationReport(payload)
