"""Deterministic replay verifier for Cisco C09 virtual-lab evidence.

The verifier re-runs the existing strict ingest boundary over the exact raw
artifact and requires byte-for-byte-derived hashes and semantic bindings to match
the supplied ingest record. Replay verification is not repository acceptance.
"""

from __future__ import annotations

import hashlib
import hmac
import json
from typing import Any, Mapping

from .validation_approval import CiscoApprovalBinding
from .virtual_lab_evidence_ingest import ingest_cisco_virtual_lab_evidence_json


class CiscoVirtualLabReplayError(ValueError):
    pass


def _canonical_sha256(value: object) -> str:
    return hashlib.sha256(
        json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("utf-8")
    ).hexdigest()


def verify_c09_ingest_replay(
    raw: str | bytes,
    *,
    ingest_record: Mapping[str, Any],
    approval: CiscoApprovalBinding,
) -> dict[str, Any]:
    if ingest_record.get("schema_version") != "cisco-c09-live-evidence-ingest/1":
        raise CiscoVirtualLabReplayError("unexpected C09 ingest schema")
    for field in (
        "repository_live_evidence_accepted",
        "repository_c09_complete",
        "physical_hardware_claimed",
        "production_writer_available",
        "production_write_authorized",
    ):
        if ingest_record.get(field) is not False:
            raise CiscoVirtualLabReplayError(f"C09 ingest record crossed safety boundary: {field}")

    recomputed = ingest_cisco_virtual_lab_evidence_json(raw, approval=approval)
    supplied = dict(ingest_record)
    if set(supplied) != set(recomputed):
        raise CiscoVirtualLabReplayError("C09 ingest record field set differs from replay")

    for key, expected in recomputed.items():
        actual = supplied.get(key)
        if isinstance(expected, str) and key.endswith("sha256"):
            if not isinstance(actual, str) or not hmac.compare_digest(actual, expected):
                raise CiscoVirtualLabReplayError(f"C09 replay mismatch: {key}")
        elif actual != expected:
            raise CiscoVirtualLabReplayError(f"C09 replay mismatch: {key}")

    result = {
        "schema_version": "cisco-c09-evidence-replay/1",
        "source_payload_sha256": recomputed["source_payload_sha256"],
        "ingest_record_sha256": recomputed["ingest_record_sha256"],
        "validated_bundle_sha256": recomputed["validated_bundle_sha256"],
        "source_sha": recomputed["source_sha"],
        "source_run_id": recomputed["source_run_id"],
        "target_id": recomputed["target_id"],
        "model": recomputed["model"],
        "iosxe_version": recomputed["iosxe_version"],
        "exact_raw_replay_verified": True,
        "repository_live_evidence_accepted": False,
        "repository_c09_complete": False,
        "physical_hardware_claimed": False,
        "production_writer_available": False,
        "production_write_authorized": False,
    }
    result["replay_record_sha256"] = _canonical_sha256(result)
    return result
