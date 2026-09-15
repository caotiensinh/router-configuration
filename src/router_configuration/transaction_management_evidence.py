from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from typing import Any, Mapping


def _canonical_sha256(value: Any) -> str:
    encoded = json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        default=str,
    ).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def _window(value: Mapping[str, Any], label: str) -> dict[str, int]:
    attempts = value.get("attempts")
    successes = value.get("successes")
    if isinstance(attempts, bool) or not isinstance(attempts, int) or attempts < 1:
        raise ValueError(f"{label}.attempts must be a positive integer")
    if isinstance(successes, bool) or not isinstance(successes, int) or not 0 <= successes <= attempts:
        raise ValueError(f"{label}.successes must be an integer from 0 through attempts")
    return {"attempts": attempts, "successes": successes}


@dataclass(frozen=True)
class ManagementReachabilityEvidence:
    payload: Mapping[str, Any]

    def as_dict(self) -> dict[str, Any]:
        return dict(self.payload)


def build_management_reachability_evidence(
    *,
    evidence_ref: str,
    before: Mapping[str, Any],
    during_apply: Mapping[str, Any],
    after: Mapping[str, Any],
    independent_session: bool,
    mutation_visible_during_apply: bool,
) -> ManagementReachabilityEvidence:
    """Normalize management reachability observations without carrying transport secrets."""

    ref = str(evidence_ref or "").strip()
    if not ref or any(marker in ref.lower() for marker in ("http://", "https://", "password", "token=")):
        raise ValueError("evidence_ref must be an opaque non-routable reference")
    windows = {
        "before": _window(before, "before"),
        "during_apply": _window(during_apply, "during_apply"),
        "after": _window(after, "after"),
    }
    all_successful = all(item["attempts"] == item["successes"] for item in windows.values())
    management_ok = bool(independent_session) and all_successful
    survival_claimed = management_ok and bool(mutation_visible_during_apply)

    payload = {
        "schema_version": "routeros-management-reachability-evidence/1",
        "evidence_ref": ref,
        "independent_session": bool(independent_session),
        "windows": windows,
        "all_probes_successful": all_successful,
        "mutation_visible_during_apply": bool(mutation_visible_during_apply),
        "management_ok": management_ok,
        "management_survival_during_apply": survival_claimed,
        "raw_routeros_payload_recorded": False,
        "secret_values_present": False,
        "transport_present": False,
        "production_writer_available": False,
        "write_authorized": False,
    }
    payload["evidence_sha256"] = _canonical_sha256(payload)
    return ManagementReachabilityEvidence(payload)
