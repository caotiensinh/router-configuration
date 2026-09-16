"""Deterministic campaign manifest for Cisco post-engineering acceptance gates.

The campaign describes execution/evidence status only. It never fabricates live
runs, physical presence, human approvals, or production-write authority.
"""

from __future__ import annotations

import hashlib
import json
import re
from typing import Any, Mapping

_GIT_SHA_RE = re.compile(r"^[0-9a-f]{40}$")
_SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
_RUN_REF_RE = re.compile(r"^[A-Za-z0-9_.:@/-]{1,160}$")

_GATE_ORDER = ("c03", "c04", "c05", "c06", "c08", "c09", "c10", "c11", "c12")
_STATUSES = frozenset({"blocked", "ready", "dispatched", "evidence_ready", "accepted"})
_EXECUTION_SURFACES = {
    "c03": ".github/workflows/cisco-netconf-live-readonly.yml",
    "c04": ".github/workflows/cisco-restconf-live-readonly.yml",
    "c05": "c05_live_state_ingest",
    "c06": ".github/workflows/cisco-switch-state-evidence-ingest.yml",
    "c08": "c08_human_approval_review",
    "c09": ".github/workflows/cisco-iosxe-virtual-lab-ingest.yml",
    "c10": ".github/workflows/cisco-recovery-observation.yml",
    "c11": ".github/workflows/cisco-physical-evidence-ingest.yml",
    "c12": "c12_handover_manifest",
}
_EXECUTION_CHAINS = {
    stage: (surface,) for stage, surface in _EXECUTION_SURFACES.items()
}
_EXECUTION_CHAINS.update(
    {
        "c05": (
            "c05_live_state_ingest",
            "c05_acceptance_decision",
        ),
        "c12": (
            "c12_handover_manifest",
            "c12_production_deployment_evidence",
            "c12_final_handover_decision",
        ),
    }
)


class CiscoAcceptanceCampaignError(ValueError):
    pass


def _canonical_sha256(value: object) -> str:
    return hashlib.sha256(
        json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
    ).hexdigest()


def _optional_sha(value: object, label: str) -> str | None:
    if value in (None, ""):
        return None
    text = str(value).strip().lower()
    if not _SHA256_RE.fullmatch(text):
        raise CiscoAcceptanceCampaignError(f"{label} must be lowercase SHA-256")
    return text


def build_acceptance_campaign_manifest(
    *,
    source_sha: str,
    gates: Mapping[str, Mapping[str, Any]],
) -> dict[str, Any]:
    source = str(source_sha).strip().lower()
    if not _GIT_SHA_RE.fullmatch(source):
        raise CiscoAcceptanceCampaignError("source_sha must be an exact 40-character Git SHA")
    if set(gates) != set(_GATE_ORDER):
        raise CiscoAcceptanceCampaignError("campaign requires exactly C03,C04,C05,C06,C08,C09,C10,C11,C12")

    normalized: dict[str, dict[str, Any]] = {}
    for stage in _GATE_ORDER:
        item = gates[stage]
        status = str(item.get("status", "")).strip().lower()
        if status not in _STATUSES:
            raise CiscoAcceptanceCampaignError(f"unsupported status for {stage}")
        if item.get("production_write_authorized") is not False:
            raise CiscoAcceptanceCampaignError(f"{stage} attempts to carry production write authority")

        run_ref = item.get("run_ref")
        if run_ref not in (None, ""):
            run_ref = str(run_ref).strip()
            if not _RUN_REF_RE.fullmatch(run_ref):
                raise CiscoAcceptanceCampaignError(f"invalid run_ref for {stage}")
        else:
            run_ref = None

        artifact_sha = _optional_sha(item.get("artifact_sha256"), f"{stage}.artifact_sha256")
        decision_sha = _optional_sha(item.get("decision_sha256"), f"{stage}.decision_sha256")
        if status in {"dispatched", "evidence_ready", "accepted"} and run_ref is None:
            raise CiscoAcceptanceCampaignError(f"{stage} status {status} requires run_ref")
        if status in {"evidence_ready", "accepted"} and artifact_sha is None:
            raise CiscoAcceptanceCampaignError(f"{stage} status {status} requires artifact_sha256")
        if status == "accepted" and decision_sha is None:
            raise CiscoAcceptanceCampaignError(f"{stage} accepted status requires decision_sha256")

        normalized[stage] = {
            "status": status,
            "execution_surface": _EXECUTION_SURFACES[stage],
            "execution_chain": list(_EXECUTION_CHAINS[stage]),
            "run_ref": run_ref,
            "artifact_sha256": artifact_sha,
            "decision_sha256": decision_sha,
        }

    accepted = [stage for stage in _GATE_ORDER if normalized[stage]["status"] == "accepted"]
    evidence_ready = [stage for stage in _GATE_ORDER if normalized[stage]["status"] == "evidence_ready"]
    result = {
        "schema_version": "cisco-acceptance-campaign/1",
        "source_sha": source,
        "gate_order": list(_GATE_ORDER),
        "gates": normalized,
        "accepted_gate_count": len(accepted),
        "evidence_ready_gate_count": len(evidence_ready),
        "all_acceptance_gates_closed": len(accepted) == len(_GATE_ORDER),
        "production_write_authorized": False,
    }
    result["campaign_sha256"] = _canonical_sha256(result)
    return result
