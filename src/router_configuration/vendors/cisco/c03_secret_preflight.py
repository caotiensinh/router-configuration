"""Sanitized secret-presence preflight for Cisco C03 live NETCONF runs.

Only secret names and presence booleans may leave this boundary. Secret values
are never copied into the returned record.
"""

from __future__ import annotations

import hashlib
import json
import re
from typing import Mapping

_SHA40 = re.compile(r"^[0-9a-f]{40}$")
_REQUIRED = (
    "CISCO_NETCONF_HOST",
    "CISCO_NETCONF_USERNAME",
    "CISCO_NETCONF_PASSWORD",
    "CISCO_NETCONF_HOSTKEY_B64",
)


class CiscoC03SecretPreflightError(ValueError):
    pass


def _canonical_sha256(value: object) -> str:
    raw = json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()


def build_c03_secret_preflight(env: Mapping[str, str], *, source_sha: str) -> dict:
    source = str(source_sha).strip().lower()
    if not _SHA40.fullmatch(source):
        raise CiscoC03SecretPreflightError("source_sha must be an exact lowercase Git SHA")

    present = {name: bool(str(env.get(name, "")).strip()) for name in _REQUIRED}
    missing = [name for name in _REQUIRED if not present[name]]
    result = {
        "schema_version": "cisco-c03-secret-preflight/1",
        "source_sha": source,
        "required_secret_names": list(_REQUIRED),
        "secret_presence": present,
        "missing_secret_names": missing,
        "ready_for_live_probe": not missing,
        "secret_values_recorded": False,
        "live_target_observed": False,
        "c03_complete": False,
        "production_write_authorized": False,
    }
    result["preflight_sha256"] = _canonical_sha256(result)
    return result
