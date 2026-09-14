from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from typing import Any, Mapping

from router_configuration.test_harness import (
    BackendKind,
    CommonScenario,
    EvidenceFidelity,
    ScenarioResult,
    TestBackendSpec,
    execute_vendor_test_plan,
    plan_vendor_tests,
)

_DNS_SCHEMA = "chr-dns-failure-evidence-summary/1"
_LINK_UP_SCHEMA = "chr-internet-down-link-up-evidence/1"
_ROUTE_LOSS_SCHEMA = "chr-route-loss-acceptance/1"

_SCHEMA_SCENARIOS = {
    _DNS_SCHEMA: CommonScenario.DNS_FAILURE,
    _LINK_UP_SCHEMA: CommonScenario.WAN_FAILOVER,
    _ROUTE_LOSS_SCHEMA: CommonScenario.DEFAULT_ROUTE_LOSS,
}

_SCENARIO_CAPABILITIES = {
    CommonScenario.DNS_FAILURE: ("dns",),
    CommonScenario.WAN_FAILOVER: ("multiwan", "routing"),
    CommonScenario.DEFAULT_ROUTE_LOSS: ("routing",),
}


def _canonical_sha256(value: Any) -> str:
    encoded = json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        default=str,
    ).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def _require_mapping(value: Any, field: str) -> Mapping[str, Any]:
    if not isinstance(value, Mapping):
        raise ValueError(f"{field} must be an object")
    return value


def _require_true(value: Any, field: str) -> None:
    if value is not True:
        raise ValueError(f"{field} must be true")


def _require_false(value: Any, field: str) -> None:
    if value is not False:
        raise ValueError(f"{field} must be false")


def _require_positive_int(value: Any, field: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value < 1:
        raise ValueError(f"{field} must be a positive integer")
    return value


def _require_sha40(value: Any, field: str) -> str:
    text = str(value or "").strip().lower()
    if len(text) != 40 or any(ch not in "0123456789abcdef" for ch in text):
        raise ValueError(f"{field} must be a 40-character commit SHA")
    return text


def _require_artifact_digest(value: Any, field: str) -> str:
    text = str(value or "").strip().lower()
    if not text.startswith("sha256:"):
        raise ValueError(f"{field} must use sha256:<digest>")
    digest = text.removeprefix("sha256:")
    if len(digest) != 64 or any(ch not in "0123456789abcdef" for ch in digest):
        raise ValueError(f"{field} must contain a 64-character SHA-256 digest")
    return text


def _require_pass(value: Any, field: str = "acceptance") -> None:
    if value != "PASS":
        raise ValueError(f"{field} must be PASS")


def _require_routeros_version(value: Any) -> str:
    version = str(value or "").strip()
    if not version:
        raise ValueError("RouterOS version is required")
    return version


def _require_all_true(value: Any, field: str, required_keys: tuple[str, ...]) -> None:
    obj = _require_mapping(value, field)
    for key in required_keys:
        _require_true(obj.get(key), f"{field}.{key}")


def _require_flow(
    value: Any,
    *,
    field: str,
    requested_key: str,
    successful_key: str,
    expected_wan10: str,
    expected_wan1: str,
) -> None:
    obj = _require_mapping(value, field)
    requested = _require_positive_int(obj.get(requested_key), f"{field}.{requested_key}")
    successful = _require_positive_int(obj.get(successful_key), f"{field}.{successful_key}")
    if requested != successful:
        raise ValueError(f"{field} must have all requested flows succeed")
    wan10 = obj.get(expected_wan10)
    wan1 = obj.get(expected_wan1)
    if isinstance(wan10, bool) or not isinstance(wan10, int):
        raise ValueError(f"{field}.{expected_wan10} must be an integer")
    if isinstance(wan1, bool) or not isinstance(wan1, int):
        raise ValueError(f"{field}.{expected_wan1} must be an integer")
    if wan10 + wan1 != successful:
        raise ValueError(f"{field} WAN flow accounting does not match successful flows")


def _validate_dns(payload: Mapping[str, Any]) -> dict[str, Any]:
    _require_pass(payload.get("acceptance"))
    version = _require_routeros_version(payload.get("routeros_version"))
    source_commit = _require_sha40(payload.get("source_commit"), "source_commit")

    workflow = _require_mapping(payload.get("workflow"), "workflow")
    if workflow.get("name") != "CHR DNS Failure":
        raise ValueError("workflow.name must be CHR DNS Failure")
    run_id = _require_positive_int(workflow.get("run_id"), "workflow.run_id")
    job_id = _require_positive_int(workflow.get("job_id"), "workflow.job_id")
    artifact_id = _require_positive_int(workflow.get("artifact_id"), "workflow.artifact_id")
    artifact_digest = _require_artifact_digest(
        workflow.get("artifact_digest"), "workflow.artifact_digest"
    )

    gates = _require_mapping(payload.get("exact_commit_gates"), "exact_commit_gates")
    for key in ("ci", "governance", "mikrotik_script_compiler"):
        _require_positive_int(gates.get(f"{key}_run_id"), f"exact_commit_gates.{key}_run_id")
        if gates.get(f"{key}_conclusion") != "success":
            raise ValueError(f"exact_commit_gates.{key}_conclusion must be success")

    dns = _require_mapping(payload.get("dns"), "dns")
    if _require_mapping(dns.get("normal"), "dns.normal").get("observed") != "success":
        raise ValueError("dns.normal.observed must be success")
    if _require_mapping(dns.get("failure"), "dns.failure").get("observed") != "timeout":
        raise ValueError("dns.failure.observed must be timeout")
    if _require_mapping(dns.get("recovery"), "dns.recovery").get("observed") != "success":
        raise ValueError("dns.recovery.observed must be success")

    connectivity = _require_mapping(payload.get("general_connectivity"), "general_connectivity")
    for phase in ("normal", "failure", "recovery"):
        _require_flow(
            connectivity.get(phase),
            field=f"general_connectivity.{phase}",
            requested_key="requested_flows",
            successful_key="successful_flows",
            expected_wan10="WAN10",
            expected_wan1="WAN1",
        )
        phase_obj = _require_mapping(connectivity.get(phase), f"general_connectivity.{phase}")
        if phase_obj.get("WAN10") != phase_obj.get("successful_flows") or phase_obj.get("WAN1") != 0:
            raise ValueError(f"general_connectivity.{phase} must remain on WAN10")

    _require_all_true(
        payload.get("semantics"),
        "semantics",
        (
            "dns_normal_success",
            "dns_failure_observed",
            "dns_recovery_success",
            "general_connectivity_remained_healthy",
            "wan10_route_remained_preferred",
            "wan10_link_remained_up",
            "wan10_dns_socket_absent_during_failure",
            "wan10_dns_socket_present_after_recovery",
        ),
    )
    safety = _require_mapping(payload.get("safety"), "safety")
    _require_false(safety.get("production_writer_available"), "safety.production_writer_available")
    _require_false(safety.get("write_authorized"), "safety.write_authorized")
    _require_false(
        safety.get("physical_router_acceptance_claimed"),
        "safety.physical_router_acceptance_claimed",
    )
    return {
        "source_commit": source_commit,
        "workflow_run_id": run_id,
        "job_id": job_id,
        "artifact_id": artifact_id,
        "artifact_digest": artifact_digest,
        "routeros_version": version,
    }


def _validate_link_up_failover(payload: Mapping[str, Any]) -> dict[str, Any]:
    _require_pass(payload.get("acceptance"))
    source = _require_mapping(payload.get("source"), "source")
    source_commit = _require_sha40(source.get("commit_sha"), "source.commit_sha")
    if source.get("workflow") != "CHR Internet Down Link Up":
        raise ValueError("source.workflow must be CHR Internet Down Link Up")
    run_id = _require_positive_int(source.get("workflow_run_id"), "source.workflow_run_id")
    job_id = _require_positive_int(source.get("job_id"), "source.job_id")
    artifact_id = _require_positive_int(source.get("artifact_id"), "source.artifact_id")
    artifact_digest = _require_artifact_digest(source.get("artifact_digest"), "source.artifact_digest")

    platform = _require_mapping(payload.get("platform"), "platform")
    if platform.get("product") != "CHR":
        raise ValueError("platform.product must be CHR")
    version = _require_routeros_version(platform.get("version"))

    readiness = _require_mapping(payload.get("readiness"), "readiness")
    _require_pass(readiness.get("acceptance"), "readiness.acceptance")
    if readiness.get("classification") != "READY":
        raise ValueError("readiness.classification must be READY")
    probe = _require_mapping(readiness.get("probe"), "readiness.probe")
    requested = _require_positive_int(probe.get("requested"), "readiness.probe.requested")
    successful = _require_positive_int(probe.get("successful"), "readiness.probe.successful")
    if requested != successful or probe.get("path") != "WAN10":
        raise ValueError("readiness probe must succeed completely through WAN10")

    _require_all_true(
        payload.get("failure_injection"),
        "failure_injection",
        (
            "upstream_packet_blackhole",
            "host_link_up",
            "namespace_link_up",
            "routeros_ether2_running",
            "management_path_independent",
        ),
    )
    phases = _require_mapping(payload.get("phases"), "phases")
    for phase in ("normal", "failover", "recovery"):
        _require_flow(
            phases.get(phase),
            field=f"phases.{phase}",
            requested_key="requested_flows",
            successful_key="successful_flows",
            expected_wan10="WAN10",
            expected_wan1="WAN1",
        )
    normal = _require_mapping(phases.get("normal"), "phases.normal")
    failover = _require_mapping(phases.get("failover"), "phases.failover")
    recovery = _require_mapping(phases.get("recovery"), "phases.recovery")
    if normal.get("WAN10") != normal.get("successful_flows") or normal.get("WAN1") != 0:
        raise ValueError("normal traffic must use WAN10")
    if failover.get("WAN1") != failover.get("successful_flows") or failover.get("WAN10") != 0:
        raise ValueError("failover traffic must use WAN1")
    if recovery.get("WAN10") != recovery.get("successful_flows") or recovery.get("WAN1") != 0:
        raise ValueError("recovery traffic must return to WAN10")
    failure = _require_mapping(phases.get("failure"), "phases.failure")
    _require_false(failure.get("preferred_wan10_route_active"), "phases.failure.preferred_wan10_route_active")
    _require_true(failure.get("backup_wan1_route_active"), "phases.failure.backup_wan1_route_active")
    _require_true(failure.get("route_failure_observed"), "phases.failure.route_failure_observed")
    _require_true(recovery.get("route_recovery_observed"), "phases.recovery.route_recovery_observed")

    safety = _require_mapping(payload.get("safety_boundary"), "safety_boundary")
    _require_false(
        safety.get("production_writer_available"),
        "safety_boundary.production_writer_available",
    )
    _require_false(safety.get("write_authorized"), "safety_boundary.write_authorized")
    _require_false(safety.get("physical_router_claimed"), "safety_boundary.physical_router_claimed")
    return {
        "source_commit": source_commit,
        "workflow_run_id": run_id,
        "job_id": job_id,
        "artifact_id": artifact_id,
        "artifact_digest": artifact_digest,
        "routeros_version": version,
    }


def _validate_route_loss(payload: Mapping[str, Any]) -> dict[str, Any]:
    _require_true(payload.get("accepted"), "accepted")
    _require_pass(payload.get("acceptance"))
    version = _require_routeros_version(payload.get("routeros_version"))
    source_commit = _require_sha40(payload.get("source_sha"), "source_sha")
    run_id = _require_positive_int(payload.get("workflow_run"), "workflow_run")
    job_id = _require_positive_int(payload.get("job_id"), "job_id")
    artifact_id = _require_positive_int(payload.get("artifact_id"), "artifact_id")
    artifact_digest = _require_artifact_digest(payload.get("artifact_digest"), "artifact_digest")

    fault = _require_mapping(payload.get("fault"), "fault")
    if fault.get("type") != "default_route_loss":
        raise ValueError("fault.type must be default_route_loss")
    route_ids = fault.get("owned_wan10_route_ids")
    if not isinstance(route_ids, list) or not route_ids or not all(str(item).strip() for item in route_ids):
        raise ValueError("fault.owned_wan10_route_ids must identify the affected owned routes")
    _require_false(fault.get("carrier_link_changed"), "fault.carrier_link_changed")
    _require_false(fault.get("upstream_blackhole_used"), "fault.upstream_blackhole_used")

    flows = _require_mapping(payload.get("flows"), "flows")
    for phase in ("normal", "route_loss", "recovery"):
        phase_obj = _require_mapping(flows.get(phase), f"flows.{phase}")
        requested = _require_positive_int(phase_obj.get("requested"), f"flows.{phase}.requested")
        successful = _require_positive_int(phase_obj.get("successful"), f"flows.{phase}.successful")
        if requested != successful:
            raise ValueError(f"flows.{phase} must have all requested flows succeed")
        egress = _require_mapping(phase_obj.get("egress"), f"flows.{phase}.egress")
        wan10 = egress.get("WAN10")
        wan1 = egress.get("WAN1")
        if isinstance(wan10, bool) or not isinstance(wan10, int):
            raise ValueError(f"flows.{phase}.egress.WAN10 must be an integer")
        if isinstance(wan1, bool) or not isinstance(wan1, int):
            raise ValueError(f"flows.{phase}.egress.WAN1 must be an integer")
        if wan10 + wan1 != successful:
            raise ValueError(f"flows.{phase} egress accounting does not match successful flows")
    normal_egress = _require_mapping(_require_mapping(flows["normal"], "flows.normal").get("egress"), "flows.normal.egress")
    loss_egress = _require_mapping(_require_mapping(flows["route_loss"], "flows.route_loss").get("egress"), "flows.route_loss.egress")
    recovery_egress = _require_mapping(_require_mapping(flows["recovery"], "flows.recovery").get("egress"), "flows.recovery.egress")
    if normal_egress.get("WAN1") != 0 or normal_egress.get("WAN10") != flows["normal"]["successful"]:
        raise ValueError("normal traffic must use WAN10")
    if loss_egress.get("WAN10") != 0 or loss_egress.get("WAN1") != flows["route_loss"]["successful"]:
        raise ValueError("route-loss traffic must fail over to WAN1")
    if recovery_egress.get("WAN1") != 0 or recovery_egress.get("WAN10") != flows["recovery"]["successful"]:
        raise ValueError("recovery traffic must fail back to WAN10")

    _require_all_true(
        payload.get("semantics"),
        "semantics",
        (
            "owned_wan10_defaults_disabled_only",
            "routeros_wan10_link_remained_up",
            "host_wan10_link_remained_up",
            "namespace_wan10_link_remained_up",
            "wan1_failover_complete",
            "same_route_ids_restored",
            "wan10_failback_complete",
        ),
    )
    _require_false(payload.get("production_writer_available"), "production_writer_available")
    _require_false(payload.get("write_authorized"), "write_authorized")
    return {
        "source_commit": source_commit,
        "workflow_run_id": run_id,
        "job_id": job_id,
        "artifact_id": artifact_id,
        "artifact_digest": artifact_digest,
        "routeros_version": version,
    }


@dataclass(frozen=True)
class ValidatedChrScenarioEvidence:
    scenario: CommonScenario
    provenance: Mapping[str, Any]
    source_evidence_sha256: str


def validate_chr_scenario_evidence(payload: Mapping[str, Any]) -> ValidatedChrScenarioEvidence:
    schema = str(payload.get("schema_version") or "")
    scenario = _SCHEMA_SCENARIOS.get(schema)
    if scenario is None:
        raise ValueError(f"unsupported CHR scenario evidence schema: {schema or '<missing>'}")

    if schema == _DNS_SCHEMA:
        provenance = _validate_dns(payload)
    elif schema == _LINK_UP_SCHEMA:
        provenance = _validate_link_up_failover(payload)
    else:
        provenance = _validate_route_loss(payload)

    return ValidatedChrScenarioEvidence(
        scenario=scenario,
        provenance=provenance,
        source_evidence_sha256=_canonical_sha256(payload),
    )


class ChrAcceptedScenarioEvidenceExecutor:
    """Project already-accepted live CHR fault evidence into the common harness."""

    vendor = "mikrotik"

    def __init__(
        self,
        *,
        backend_id: str,
        validated: ValidatedChrScenarioEvidence,
        evidence_ref: str,
    ) -> None:
        self.backend_id = str(backend_id)
        self._validated = validated
        self._evidence_ref = str(evidence_ref)
        if not self._evidence_ref.strip():
            raise ValueError("evidence_ref is required")

    def run_scenario(self, scenario: CommonScenario) -> ScenarioResult:
        if scenario is not self._validated.scenario:
            raise ValueError(
                f"CHR evidence is bound to {self._validated.scenario.value}, not {scenario.value}"
            )
        return ScenarioResult.build(
            scenario=scenario,
            passed=True,
            evidence_ref=self._evidence_ref,
            fidelity=EvidenceFidelity.VENDOR_OS,
        )


def build_chr_scenario_test_bundle(
    payload: Mapping[str, Any],
    *,
    evidence_ref: str,
    backend_id: str = "mikrotik-chr-fault-lab",
) -> dict[str, Any]:
    """Create one plan-scoped common-harness assessment from accepted CHR evidence."""

    validated = validate_chr_scenario_evidence(payload)
    backend = TestBackendSpec.build(
        backend_id=backend_id,
        vendor="mikrotik",
        kind=BackendKind.VIRTUAL_APPLIANCE,
        fidelity=EvidenceFidelity.VENDOR_OS,
        capabilities=_SCENARIO_CAPABILITIES[validated.scenario],
        hardware_present=False,
        lab_disposable=True,
        fault_injection_allowed=True,
        snapshot_restore_available=False,
        production_write_authorized=False,
    )
    plan = plan_vendor_tests(backend, (validated.scenario,))
    executor = ChrAcceptedScenarioEvidenceExecutor(
        backend_id=backend.backend_id,
        validated=validated,
        evidence_ref=evidence_ref,
    )
    assessment = execute_vendor_test_plan(plan, executor).as_dict()
    bundle = {
        "schema_version": "mikrotik-chr-fault-scenario-common-test-bridge/1",
        "source_schema_version": str(payload["schema_version"]),
        "source_evidence_sha256": validated.source_evidence_sha256,
        "source_provenance": dict(validated.provenance),
        "scenario": validated.scenario.value,
        "plan": plan.as_dict(),
        "assessment": assessment,
        "scenario_scope_acceptance_passed": bool(assessment["software_acceptance_passed"]),
        "whole_vendor_software_certification_claimed": False,
        "hardware_certification_claimed": False,
        "production_writer_available": False,
        "write_authorized": False,
    }
    bundle["bundle_sha256"] = _canonical_sha256(bundle)
    return bundle
