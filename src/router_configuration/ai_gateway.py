from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from typing import Any, Mapping


class TelemetryTopic(str, Enum):
    DEVICE_STATE = "device_state"
    INTERFACE_COUNTERS = "interface_counters"
    WAN_HEALTH = "wan_health"
    ROUTING = "routing"
    FIREWALL_STATS = "firewall_stats"
    QOS_STATS = "qos_stats"
    VPN_STATUS = "vpn_status"
    LOG_SUMMARY = "log_summary"
    FLOW_METADATA = "flow_metadata"
    PACKET_METADATA = "packet_metadata"
    RAW_PACKET = "raw_packet"
    HARNESS_EVIDENCE = "harness_evidence"


class RecommendationKind(str, Enum):
    OBSERVATION = "observation"
    DIAGNOSIS = "diagnosis"
    MAINTENANCE = "maintenance"
    CAPACITY = "capacity"
    SECURITY = "security"
    PROPOSED_INTENT = "proposed_intent"


@dataclass(frozen=True)
class AIGatewayPolicy:
    allow_raw_packet_payload: bool = False
    allow_direct_device_write: bool = False


@dataclass(frozen=True)
class TelemetryEnvelope:
    schema_version: str
    device_id: str
    topic: TelemetryTopic
    payload: Mapping[str, Any]
    run_id: str | None = None
    redacted: bool = True


@dataclass(frozen=True)
class AIRecommendation:
    kind: RecommendationKind
    title: str
    summary: str
    confidence: float | None = None
    proposed_intent: Mapping[str, Any] | None = None


@dataclass(frozen=True)
class GatewayDecision:
    accepted: bool
    reasons: tuple[str, ...] = ()


class AIGateway:
    """Advisory-only future AI integration boundary."""

    _SENSITIVE_TOKENS = (
        "password", "passwd", "private_key", "preshared_key", "psk",
        "token", "secret", "credential",
    )

    def __init__(self, policy: AIGatewayPolicy | None = None) -> None:
        self.policy = policy or AIGatewayPolicy()
        if self.policy.allow_direct_device_write:
            raise ValueError("AI gateway cannot enable direct device writes")

    def _scan_sensitive(self, value: Any, path: str = "payload") -> list[str]:
        findings: list[str] = []
        if isinstance(value, Mapping):
            for key, child in value.items():
                child_path = f"{path}.{key}"
                lowered = str(key).lower()
                if any(token in lowered for token in self._SENSITIVE_TOKENS):
                    findings.append(child_path)
                findings.extend(self._scan_sensitive(child, child_path))
        elif isinstance(value, (list, tuple)):
            for index, child in enumerate(value):
                findings.extend(self._scan_sensitive(child, f"{path}[{index}]"))
        return findings

    def accept_telemetry(self, envelope: TelemetryEnvelope) -> GatewayDecision:
        reasons: list[str] = []
        if not envelope.schema_version.strip():
            reasons.append("schema_version is required")
        if not envelope.device_id.strip():
            reasons.append("device_id is required")
        if not envelope.redacted:
            reasons.append("telemetry must be marked redacted")
        if envelope.topic is TelemetryTopic.RAW_PACKET and not self.policy.allow_raw_packet_payload:
            reasons.append("raw packet payload is disabled by gateway policy")
        sensitive_paths = self._scan_sensitive(envelope.payload)
        if sensitive_paths:
            reasons.append("sensitive fields are not allowed: " + ", ".join(sensitive_paths))
        return GatewayDecision(not reasons, tuple(reasons))

    def accept_recommendation(self, recommendation: AIRecommendation) -> GatewayDecision:
        reasons: list[str] = []
        if not recommendation.title.strip():
            reasons.append("recommendation title is required")
        if not recommendation.summary.strip():
            reasons.append("recommendation summary is required")
        if recommendation.confidence is not None and not 0.0 <= recommendation.confidence <= 1.0:
            reasons.append("confidence must be between 0 and 1")
        if recommendation.kind is RecommendationKind.PROPOSED_INTENT and recommendation.proposed_intent is None:
            reasons.append("proposed_intent recommendation requires an intent payload")
        if recommendation.proposed_intent is not None:
            sensitive_paths = self._scan_sensitive(recommendation.proposed_intent, "proposed_intent")
            if sensitive_paths:
                reasons.append("proposed intent contains sensitive fields: " + ", ".join(sensitive_paths))
        return GatewayDecision(not reasons, tuple(reasons))

    @staticmethod
    def execution_route_for(recommendation: AIRecommendation) -> tuple[str, ...]:
        if recommendation.kind is RecommendationKind.PROPOSED_INTENT:
            return ("intent_review", "plan", "validate", "safety_gate", "approval")
        return ("advisory_only",)
