"""Sanitized secret-presence preflight for Cisco C04 live RESTCONF runs.

The preflight reports names/presence only. It requires the runtime credentials
and independent platform-binding inputs needed for C04 acceptance, while keeping
CA/certificate pinning optional because system trust roots remain valid.
"""

from __future__ import annotations

import hashlib
import json
import re
from typing import Mapping

_SHA40 = re.compile(r"^[0-9a-f]{40}$")
_REQUIRED = (
    "CISCO_RESTCONF_HOST",
    "CISCO_RESTCONF_USERNAME",
    "CISCO_RESTCONF_PASSWORD",
    "CISCO_RESTCONF_PLATFORM_MODEL",
    "CISCO_RESTCONF_PLATFORM_TARGET_SHA256",
    "CISCO_RESTCONF_PLATFORM_EVIDENCE_SHA256",
)
_OPTIONAL_SECURITY = (
    "CISCO_RESTCONF_CA_PEM_B64",
    "CISCO_RESTCONF_CERT_SHA256",
)


class CiscoC04SecretPreflightError(ValueError):
    pass


def _canonical_sha256(value: object) -> str:
    raw = json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()


def build_c04_secret_preflight(env: Mapping[str, str], *, source_sha: str) -> dict:
    source = str(source_sha).strip().lower()
    if not _SHA40.fullmatch(source):
        raise CiscoC04SecretPreflightError("source_sha must be an exact lowercase Git SHA")

    required_presence = {name: bool(str(env.get(name, "")).strip()) for name in _REQUIRED}
    optional_presence = {name: bool(str(env.get(name, "")).strip()) for name in _OPTIONAL_SECURITY}
    missing = [name for name in _REQUIRED if not required_presence[name]]
    result = {
        "schema_version": "cisco-c04-secret-preflight/1",
        "source_sha": source,
        "required_secret_names": list(_REQUIRED),
        "required_secret_presence": required_presence,
        "optional_security_secret_names": list(_OPTIONAL_SECURITY),
        "optional_security_secret_presence": optional_presence,
        "missing_required_secret_names": missing,
        "ready_for_live_acceptance_probe": not missing,
        "secret_values_recorded": False,
        "live_target_observed": False,
        "c04_complete": False,
        "production_write_authorized": False,
    }
    result["preflight_sha256"] = _canonical_sha256(result)
    return result
