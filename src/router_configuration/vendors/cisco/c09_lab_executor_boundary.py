"""Fail-closed pre-execution boundary for Cisco C09 controlled virtual lab.

This module authorizes nothing in production and contains no transport. It binds a
single C09 lab execution request to the exact accepted C08 approval, admitted
Catalyst 8000V identity, source commit, operator attestation, and required lab
scenarios before a later runtime executor may be considered.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import re
from typing import Any, Mapping

from .platforms import CiscoDeviceRole, assess_read_only_candidate
from .validation_approval import CiscoApprovalBinding, validate_approval_fingerprint

_REQUEST_SCHEMA = "cisco-c09-lab-execution-request/1"
_BOUNDARY_SCHEMA = "cisco-c09-lab-execution-boundary/1"
_C8000V_SOURCE_ID = "CISCO-C8000V-INSTALL"
_REQUIRED_SCENARIOS = (
    "read_only_discovery",
    "render_validate",
    "configuration_roundtrip",
    "management_survival",
)
_GIT_SHA_RE = re.compile(r"^[0-9a-f]{40}$")
_SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
_REF_RE = re.compile(r"^[A-Za-z0-9_.:@/-]{1,160}$")


class CiscoC09LabExecutionBoundaryError(ValueError):
    """Raised when a C09 lab execution request is not safely executable."""


def _canonical_sha256(value: object) -> str:
    raw = json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        default=str,
    ).encode("utf-8")
    return hashlib.sha256(raw).hexdigest()


def _sha256(value: object, label: str) -> str:
    text = str(value or "").strip().lower()
    if not _SHA256_RE.fullmatch(text):
        raise CiscoC09LabExecutionBoundaryError(f"{label} must be lowercase SHA-256")
    return text


def _ref(value: object, label: str) -> str:
    text = str(value or "").strip()
    if not _REF_RE.fullmatch(text):
        raise CiscoC09LabExecutionBoundaryError(f"invalid {label}")
    lowered = text.lower()
    if any(marker in lowered for marker in ("password", "token", "secret", "private_key", "http://", "https://")):
        raise CiscoC09LabExecutionBoundaryError(f"{label} contains endpoint or secret material")
    return text


def _verify_c08_decision(
    decision: Mapping[str, Any],
    *,
    approval: CiscoApprovalBinding,
) -> str:
    if decision.get("schema_version") != "cisco-c08-repository-acceptance-decision/1":
        raise CiscoC09LabExecutionBoundaryError("unexpected C08 decision schema")

    supplied = _sha256(decision.get("decision_record_sha256"), "decision_record_sha256")
    unsigned = dict(decision)
    unsigned.pop("decision_record_sha256", None)
    if not hmac.compare_digest(supplied, _canonical_sha256(unsigned)):
        raise CiscoC09LabExecutionBoundaryError("C08 decision digest mismatch")

    if decision.get("decision") != "accept":
        raise CiscoC09LabExecutionBoundaryError("C09 lab execution requires accepted C08 decision")
    for field in ("human_approved", "approval_bound", "c08_complete"):
        if decision.get(field) is not True:
            raise CiscoC09LabExecutionBoundaryError(f"C08 decision is incomplete: {field}")
    for field in ("apply_authorized", "write_authorized", "production_write_authorized"):
        if decision.get(field) is not False:
            raise CiscoC09LabExecutionBoundaryError(f"C08 decision crossed write boundary: {field}")

    expected = {
        "change_id": approval.change_id,
        "target_id": approval.target_id,
        "pre_state_sha256": approval.pre_state_sha256,
        "approval_sha256": approval.approval_sha256,
    }
    for field, value in expected.items():
        if str(decision.get(field, "")).strip() != value:
            raise CiscoC09LabExecutionBoundaryError(f"C08 decision does not match approval binding: {field}")
    validate_approval_fingerprint(approval, str(decision.get("approval_sha256", "")))
    return supplied


def build_c09_lab_execution_boundary(
    request: Mapping[str, Any],
    *,
    approval: CiscoApprovalBinding,
    c08_decision: Mapping[str, Any],
    source_sha: str,
) -> dict[str, Any]:
    """Bind one exact C09 request to accepted C08 evidence without executing it."""

    source = str(source_sha or "").strip().lower()
    if not _GIT_SHA_RE.fullmatch(source):
        raise CiscoC09LabExecutionBoundaryError("source_sha must be exact lowercase Git SHA")
    if request.get("schema_version") != _REQUEST_SCHEMA:
        raise CiscoC09LabExecutionBoundaryError("unexpected C09 lab execution request schema")
    if str(request.get("source_sha", "")).strip().lower() != source:
        raise CiscoC09LabExecutionBoundaryError("request source SHA differs from execution source")

    request_id = _ref(request.get("request_id"), "request_id")
    operator_ref = _ref(request.get("operator_ref"), "operator_ref")
    operator_attestation = _sha256(
        request.get("operator_attestation_sha256"),
        "operator_attestation_sha256",
    )
    image_identity = _sha256(request.get("image_identity_sha256"), "image_identity_sha256")
    if request.get("image_source_id") != _C8000V_SOURCE_ID:
        raise CiscoC09LabExecutionBoundaryError("C8000V image provenance is not bound to approved Cisco source")

    decision_sha = _verify_c08_decision(c08_decision, approval=approval)

    if approval.approval_bound or approval.human_approved or approval.c08_complete:
        raise CiscoC09LabExecutionBoundaryError("approval binding must remain immutable pre-acceptance fingerprint")
    if approval.apply_authorized or approval.write_authorized or approval.production_write_authorized:
        raise CiscoC09LabExecutionBoundaryError("approval binding carries prohibited write authority")
    if approval.target_datastore != "candidate":
        raise CiscoC09LabExecutionBoundaryError("C09 lab execution requires candidate datastore")

    target_id = _ref(request.get("target_id"), "target_id")
    if target_id != approval.target_id:
        raise CiscoC09LabExecutionBoundaryError("request target differs from C08 approval")
    model = str(request.get("model") or "").strip()
    version = str(request.get("iosxe_version") or "").strip()
    if model != approval.model or version != approval.iosxe_version:
        raise CiscoC09LabExecutionBoundaryError("request model/version differs from C08 approval")

    admission = assess_read_only_candidate(model, version)
    if not admission.read_only_candidate:
        raise CiscoC09LabExecutionBoundaryError(f"C09 lab platform/version not admitted: {admission.status}")
    if admission.family != "Catalyst 8000V" or admission.role is not CiscoDeviceRole.ROUTER:
        raise CiscoC09LabExecutionBoundaryError("C09 controlled executor is bounded to Catalyst 8000V")
    if approval.platform_family != "Catalyst 8000V" or approval.role != "router":
        raise CiscoC09LabExecutionBoundaryError("C08 approval is not bound to Catalyst 8000V router")
    if admission.documentation_train != approval.documentation_train:
        raise CiscoC09LabExecutionBoundaryError("documentation train differs from C08 approval")

    for field in ("lab_disposable", "lab_only", "operator_confirmed_lab_scope"):
        if request.get(field) is not True:
            raise CiscoC09LabExecutionBoundaryError(f"{field} must be true")
    for field in (
        "production_target",
        "hardware_present",
        "image_embedded_in_repository",
        "license_material_present",
        "production_writer_available",
        "production_write_authorized",
    ):
        if request.get(field) is not False:
            raise CiscoC09LabExecutionBoundaryError(f"{field} must remain false")
    if request.get("backend_kind") != "virtual_appliance":
        raise CiscoC09LabExecutionBoundaryError("C09 controlled executor requires virtual_appliance backend")

    raw_scenarios = request.get("requested_scenarios")
    if not isinstance(raw_scenarios, list):
        raise CiscoC09LabExecutionBoundaryError("requested_scenarios must be a list")
    scenarios = tuple(str(item).strip() for item in raw_scenarios)
    if len(scenarios) != len(set(scenarios)):
        raise CiscoC09LabExecutionBoundaryError("requested_scenarios contains duplicates")
    if set(scenarios) != set(_REQUIRED_SCENARIOS):
        raise CiscoC09LabExecutionBoundaryError("requested_scenarios must exactly match the C09 required set")

    result = {
        "schema_version": _BOUNDARY_SCHEMA,
        "request_id": request_id,
        "source_sha": source,
        "target_id": target_id,
        "model": model,
        "iosxe_version": version,
        "documentation_train": approval.documentation_train,
        "platform_family": approval.platform_family,
        "role": approval.role,
        "change_id": approval.change_id,
        "approval_sha256": approval.approval_sha256,
        "c08_decision_sha256": decision_sha,
        "pre_state_sha256": approval.pre_state_sha256,
        "payload_digest_sha256": approval.payload_digest_sha256,
        "schema_inventory_digest_sha256": approval.schema_inventory_digest_sha256,
        "image_source_id": _C8000V_SOURCE_ID,
        "image_identity_sha256": image_identity,
        "operator_ref": operator_ref,
        "operator_attestation_sha256": operator_attestation,
        "requested_scenarios": list(_REQUIRED_SCENARIOS),
        "backend_kind": "virtual_appliance",
        "lab_disposable": True,
        "lab_only": True,
        "eligible_for_controlled_lab_execution": True,
        "runtime_transport_present": False,
        "live_execution_observed": False,
        "c09_complete": False,
        "physical_hardware_claimed": False,
        "production_writer_available": False,
        "production_write_authorized": False,
    }
    result["boundary_record_sha256"] = _canonical_sha256(result)
    return result
