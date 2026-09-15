from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from typing import Any, Mapping

from .knowledge import MikroTikOfflineKnowledge


class MikroTikReferenceStatus(str, Enum):
    PASS = "pass"
    FAIL = "fail"
    MISSING = "missing"


@dataclass(frozen=True)
class MikroTikReferenceRule:
    rule_id: str
    evidence_key: str
    description: str
    knowledge_id: str
    required_post: bool = True


@dataclass(frozen=True)
class MikroTikReferenceResult:
    rule: MikroTikReferenceRule
    status: MikroTikReferenceStatus
    observed: Any
    source_url: str

    def as_dict(self) -> dict[str, Any]:
        return {
            "rule_id": self.rule.rule_id,
            "evidence_key": self.rule.evidence_key,
            "description": self.rule.description,
            "knowledge_id": self.rule.knowledge_id,
            "source_url": self.source_url,
            "status": self.status.value,
            "observed": self.observed,
        }


@dataclass(frozen=True)
class MikroTikReferenceEvaluation:
    phase: str
    intent_kind: str
    results: tuple[MikroTikReferenceResult, ...]

    @property
    def passed(self) -> bool:
        required = [item for item in self.results if item.rule.required_post]
        return bool(required) and all(item.status is MikroTikReferenceStatus.PASS for item in required)

    def as_dict(self) -> dict[str, Any]:
        return {
            "schema_version": "mikrotik-reference-evaluation/1",
            "phase": self.phase,
            "intent_kind": self.intent_kind,
            "passed": self.passed,
            "results": [item.as_dict() for item in self.results],
        }


@dataclass(frozen=True)
class MikroTikReferenceComparison:
    pre: MikroTikReferenceEvaluation
    post: MikroTikReferenceEvaluation
    fixed: tuple[str, ...]
    regressed: tuple[str, ...]
    unchanged_pass: tuple[str, ...]
    remaining_nonconformant: tuple[str, ...]

    @property
    def post_ready(self) -> bool:
        return self.post.passed and not self.regressed and not self.remaining_nonconformant

    def as_dict(self) -> dict[str, Any]:
        return {
            "schema_version": "mikrotik-pre-post-reference-comparison/1",
            "post_ready": self.post_ready,
            "fixed": list(self.fixed),
            "regressed": list(self.regressed),
            "unchanged_pass": list(self.unchanged_pass),
            "remaining_nonconformant": list(self.remaining_nonconformant),
            "pre": self.pre.as_dict(),
            "post": self.post.as_dict(),
        }


_COMMON_RULES = (
    MikroTikReferenceRule(
        "provenance.routeros-version",
        "routeros_version_recorded",
        "Target RouterOS version is recorded before generation and with deployment evidence.",
        "configuration-management",
    ),
    MikroTikReferenceRule(
        "provenance.knowledge",
        "knowledge_version_recorded",
        "The local MikroTik knowledge/source provenance used for the deployment is recorded.",
        "cli-reference",
    ),
    MikroTikReferenceRule(
        "management.path",
        "management_path_survives",
        "Approved management reachability survives the configuration transaction.",
        "safe-mode",
    ),
    MikroTikReferenceRule(
        "desired.actual",
        "post_state_matches_desired",
        "Read-back state matches the validated desired state after apply.",
        "configuration-management",
    ),
)

_SECURE_INTERNET_RULES = (
    MikroTikReferenceRule(
        "firewall.established-related",
        "established_related_preserved",
        "Established and related return traffic is preserved.",
        "firewall-stateful",
    ),
    MikroTikReferenceRule(
        "firewall.invalid",
        "invalid_state_dropped",
        "Invalid connection state is dropped.",
        "firewall-stateful",
    ),
    MikroTikReferenceRule(
        "firewall.wan-lan",
        "unsolicited_wan_to_lan_denied",
        "Unsolicited WAN-to-LAN forwarding is denied by default.",
        "firewall-stateful",
    ),
    MikroTikReferenceRule(
        "management.wan",
        "wan_management_denied",
        "Router management is not exposed from WAN unless explicitly required.",
        "router-hardening",
    ),
    MikroTikReferenceRule(
        "management.sources",
        "management_sources_restricted",
        "Management access is restricted to approved source networks.",
        "router-hardening",
    ),
    MikroTikReferenceRule(
        "connectivity.lan-internet",
        "lan_can_reach_internet",
        "LAN-initiated Internet connectivity works after policy is applied.",
        "firewall-stateful",
    ),
    MikroTikReferenceRule(
        "idempotency",
        "desired_state_idempotent",
        "A second plan against the achieved state requires no duplicate change.",
        "configuration-management",
    ),
)

_WIREGUARD_RULES = (
    MikroTikReferenceRule(
        "wireguard.allowed-address",
        "wireguard_allowed_addresses_non_overlapping",
        "WireGuard peer allowed-address ranges do not overlap on the interface.",
        "wireguard-peers",
    ),
    MikroTikReferenceRule(
        "wireguard.handshake",
        "wireguard_handshake_recent",
        "The site-to-site WireGuard peer has a recent successful handshake.",
        "wireguard-peers",
    ),
    MikroTikReferenceRule(
        "wireguard.bidirectional",
        "site_lans_bidirectionally_reachable",
        "Declared site LANs are reachable in both directions.",
        "wireguard-peers",
    ),
    MikroTikReferenceRule(
        "wireguard.local-breakout",
        "internet_default_route_remains_local",
        "Internet default routing remains local when the intent requests local breakout.",
        "wireguard-peers",
    ),
    MikroTikReferenceRule(
        "wireguard.scope",
        "undeclared_vpn_forwarding_denied",
        "Forwarding outside the declared site-to-site scope is denied.",
        "wireguard-peers",
    ),
    MikroTikReferenceRule(
        "idempotency",
        "desired_state_idempotent",
        "A second plan against the achieved state requires no duplicate change.",
        "configuration-management",
    ),
)


def reference_rules(intent_kind: str) -> tuple[MikroTikReferenceRule, ...]:
    key = intent_kind.strip().lower()
    if key == "secure_internet_gateway":
        return (*_COMMON_RULES, *_SECURE_INTERNET_RULES)
    if key == "site_to_site_wireguard":
        return (*_COMMON_RULES, *_WIREGUARD_RULES)
    raise ValueError(f"unsupported MikroTik reference intent: {intent_kind}")


def evaluate_reference(
    *,
    intent_kind: str,
    evidence: Mapping[str, Any],
    phase: str,
    knowledge: MikroTikOfflineKnowledge | None = None,
) -> MikroTikReferenceEvaluation:
    if phase not in {"pre", "post"}:
        raise ValueError("phase must be pre or post")
    store = knowledge or MikroTikOfflineKnowledge.bundled()
    results: list[MikroTikReferenceResult] = []
    for rule in reference_rules(intent_kind):
        source = store.get(rule.knowledge_id)
        if rule.evidence_key not in evidence:
            status = MikroTikReferenceStatus.MISSING
            observed = None
        else:
            observed = evidence.get(rule.evidence_key)
            status = MikroTikReferenceStatus.PASS if observed is True else MikroTikReferenceStatus.FAIL
        results.append(MikroTikReferenceResult(rule, status, observed, source.source_url))
    return MikroTikReferenceEvaluation(phase, intent_kind, tuple(results))


def compare_pre_post(
    pre: MikroTikReferenceEvaluation,
    post: MikroTikReferenceEvaluation,
) -> MikroTikReferenceComparison:
    if pre.intent_kind != post.intent_kind:
        raise ValueError("pre/post intent_kind must match")
    pre_map = {item.rule.rule_id: item.status for item in pre.results}
    post_map = {item.rule.rule_id: item.status for item in post.results}
    if set(pre_map) != set(post_map):
        raise ValueError("pre/post reference rule sets must match")

    fixed: list[str] = []
    regressed: list[str] = []
    unchanged_pass: list[str] = []
    remaining: list[str] = []
    for rule_id in sorted(pre_map):
        before = pre_map[rule_id]
        after = post_map[rule_id]
        if after is MikroTikReferenceStatus.PASS:
            if before is MikroTikReferenceStatus.PASS:
                unchanged_pass.append(rule_id)
            else:
                fixed.append(rule_id)
        elif before is MikroTikReferenceStatus.PASS:
            regressed.append(rule_id)
        else:
            remaining.append(rule_id)
    return MikroTikReferenceComparison(
        pre=pre,
        post=post,
        fixed=tuple(fixed),
        regressed=tuple(regressed),
        unchanged_pass=tuple(unchanged_pass),
        remaining_nonconformant=tuple(remaining),
    )


def measure_pre_post(
    *,
    intent_kind: str,
    pre_evidence: Mapping[str, Any],
    post_evidence: Mapping[str, Any],
    knowledge: MikroTikOfflineKnowledge | None = None,
) -> MikroTikReferenceComparison:
    store = knowledge or MikroTikOfflineKnowledge.bundled()
    pre = evaluate_reference(intent_kind=intent_kind, evidence=pre_evidence, phase="pre", knowledge=store)
    post = evaluate_reference(intent_kind=intent_kind, evidence=post_evidence, phase="post", knowledge=store)
    return compare_pre_post(pre, post)
