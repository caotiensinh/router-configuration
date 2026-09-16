from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass
from typing import Any, Mapping, Sequence

_SHA1 = re.compile(r"^[0-9a-f]{40}$")
_SHA256 = re.compile(r"^[0-9a-f]{64}$")
_FORBIDDEN = frozenset({
    "password", "credential", "credentials", "credential_ref", "token", "access_token",
    "refresh_token", "client_secret", "secret", "shared_secret", "private_key",
    "preshared_key", "psk", "command", "commands", "shell", "transport", "writer",
})

class AsBuiltDocumentationError(ValueError):
    pass

def _digest(value: Any) -> str:
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False, default=str).encode("utf-8")).hexdigest()

def _reject_sensitive(value: Any, path: str = "as_built") -> None:
    if isinstance(value, Mapping):
        for key, child in value.items():
            name = str(key).strip().lower()
            if name in _FORBIDDEN or any(marker in name for marker in ("password", "private_key", "client_secret", "access_token", "refresh_token")):
                raise AsBuiltDocumentationError(f"{path} contains forbidden secret/runtime field: {key}")
            _reject_sensitive(child, f"{path}.{key}")
    elif isinstance(value, (list, tuple)):
        for index, child in enumerate(value):
            _reject_sensitive(child, f"{path}[{index}]")

def _strings(values: Sequence[Any], label: str) -> list[str]:
    out=[str(v).strip() for v in values]
    if not out or any(not item or any(c in item for c in ("\n","\r","\x00")) for item in out):
        raise AsBuiltDocumentationError(f"{label} must contain non-empty safe values")
    if len(out) != len(set(out)):
        raise AsBuiltDocumentationError(f"{label} must be unique")
    return out

def _admit_summary(summary: Mapping[str, Any]) -> str:
    if summary.get("claim") != "durable_project_summary_only":
        raise AsBuiltDocumentationError("project_summary must be the durable non-authorizing summary")
    sha=str(summary.get("current_main") or "").strip().lower()
    if not _SHA1.fullmatch(sha):
        raise AsBuiltDocumentationError("project_summary current_main must be a lowercase SHA-1")
    if summary.get("candidate_work_counted") is not False or summary.get("write_authorized") is not False:
        raise AsBuiltDocumentationError("project_summary must not count candidate work or authorize writes")
    return sha

def _admit_configuration_report(report: Mapping[str, Any], main_sha: str) -> str:
    if report.get("claim") != "verified_configuration_report_only":
        raise AsBuiltDocumentationError("configuration_report must be verified and non-authorizing")
    if str(report.get("current_main") or "").strip().lower() != main_sha:
        raise AsBuiltDocumentationError("summary and configuration report must bind the same main SHA")
    if report.get("fresh_independent_readback_required") is not True:
        raise AsBuiltDocumentationError("configuration report must require fresh independent readback")
    if report.get("secret_material_included") is not False or report.get("write_authorized") is not False:
        raise AsBuiltDocumentationError("configuration report must exclude secrets and write authority")
    digest=str(report.get("configuration_report_sha256") or "").strip().lower()
    if not _SHA256.fullmatch(digest):
        raise AsBuiltDocumentationError("configuration_report_sha256 must be a lowercase SHA-256")
    return digest

@dataclass(frozen=True)
class AsBuiltDocumentation:
    payload: Mapping[str, Any]
    def as_dict(self) -> dict[str, Any]:
        return dict(self.payload)

def build_as_built_documentation(
    *,
    project_summary: Mapping[str, Any],
    configuration_report: Mapping[str, Any],
    topology: Mapping[str, Any],
    inventory: Sequence[Mapping[str, Any]],
    management_paths: Sequence[str],
    evidence_refs: Sequence[str],
    known_deviations: Sequence[str] = (),
) -> AsBuiltDocumentation:
    if not isinstance(project_summary, Mapping) or not isinstance(configuration_report, Mapping):
        raise AsBuiltDocumentationError("upstream reports must be objects")
    main_sha=_admit_summary(project_summary)
    report_digest=_admit_configuration_report(configuration_report, main_sha)
    if not isinstance(topology, Mapping) or not topology:
        raise AsBuiltDocumentationError("topology must be a non-empty object")
    if not inventory:
        raise AsBuiltDocumentationError("inventory must not be empty")
    _reject_sensitive(topology, "topology")
    _reject_sensitive(inventory, "inventory")
    paths=_strings(management_paths, "management_paths")
    refs=_strings(evidence_refs, "evidence_refs")
    devs=[str(v).strip() for v in known_deviations]
    if any(not item or "\x00" in item for item in devs):
        raise AsBuiltDocumentationError("known_deviations contains an unsafe value")
    canonical_topology=json.loads(json.dumps(topology, sort_keys=True, separators=(",",":"), ensure_ascii=False, default=str))
    canonical_inventory=json.loads(json.dumps(list(inventory), sort_keys=True, separators=(",",":"), ensure_ascii=False, default=str))
    payload={
        "schema_version":"omada-as-built-documentation/1",
        "current_main":main_sha,
        "source_configuration_report_sha256":report_digest,
        "topology":canonical_topology,
        "inventory":canonical_inventory,
        "management_paths":paths,
        "known_deviations":devs,
        "evidence_refs":refs,
        "claim":"verified_as_built_documentation_only",
        "generated_from_verified_configuration_report":True,
        "secret_material_included":False,
        "transport_present":False,
        "apply_available":False,
        "rollback_available":False,
        "production_writer_available":False,
        "write_authorized":False,
    }
    payload["topology_sha256"]=_digest(canonical_topology)
    payload["inventory_sha256"]=_digest(canonical_inventory)
    payload["as_built_sha256"]=_digest(payload)
    return AsBuiltDocumentation(payload)
