from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from typing import Any

from .command_effects import validate_effect_order
from .script_planner import (
    MikroTikOrderingProposal,
    MikroTikScriptArtifact,
    MikroTikScriptContract,
    MikroTikScriptPlanError,
    validate_ordering,
)


@dataclass(frozen=True)
class MikroTikSemanticFinding:
    code: str
    message: str
    command_ids: tuple[str, ...]

    def as_dict(self) -> dict[str, Any]:
        return {
            "code": self.code,
            "message": self.message,
            "command_ids": list(self.command_ids),
        }


@dataclass(frozen=True)
class MikroTikSemanticAttestation:
    render_sha256: str
    script_sha256: str
    ordered_command_ids: tuple[str, ...]
    passed: bool
    findings: tuple[MikroTikSemanticFinding, ...]

    @property
    def attestation_sha256(self) -> str:
        payload = {
            "render_sha256": self.render_sha256,
            "script_sha256": self.script_sha256,
            "ordered_command_ids": list(self.ordered_command_ids),
            "passed": self.passed,
            "findings": [item.as_dict() for item in self.findings],
        }
        raw = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")
        return hashlib.sha256(raw).hexdigest()

    def as_dict(self) -> dict[str, Any]:
        return {
            "schema_version": "mikrotik-semantic-attestation/1",
            "render_sha256": self.render_sha256,
            "script_sha256": self.script_sha256,
            "ordered_command_ids": list(self.ordered_command_ids),
            "passed": self.passed,
            "findings": [item.as_dict() for item in self.findings],
            "attestation_sha256": self.attestation_sha256,
        }


def _ordered_source_ids(contract: MikroTikScriptContract, *, section: str) -> tuple[str, ...]:
    rows = sorted(
        (item for item in contract.commands if item.section == section),
        key=lambda item: item.source_index,
    )
    return tuple(item.command_id for item in rows)


def _ordered_proposal_ids(
    contract: MikroTikScriptContract,
    proposal: MikroTikOrderingProposal,
    *,
    section: str,
) -> tuple[str, ...]:
    section_ids = {item.command_id for item in contract.commands if item.section == section}
    return tuple(cid for cid in proposal.ordered_command_ids if cid in section_ids)


def _section_order_findings(
    contract: MikroTikScriptContract,
    proposal: MikroTikOrderingProposal,
) -> list[MikroTikSemanticFinding]:
    findings: list[MikroTikSemanticFinding] = []
    sections = sorted({item.section for item in contract.commands})
    for section in sections:
        expected = _ordered_source_ids(contract, section=section)
        observed = _ordered_proposal_ids(contract, proposal, section=section)
        if expected != observed:
            findings.append(
                MikroTikSemanticFinding(
                    "section_order_changed",
                    f"AI ordering changed deterministic renderer order inside RouterOS section {section!r}",
                    observed,
                )
            )
    return findings


def _effect_graph_findings(
    contract: MikroTikScriptContract,
    proposal: MikroTikOrderingProposal,
) -> list[MikroTikSemanticFinding]:
    return [
        MikroTikSemanticFinding(
            item.code,
            item.detail,
            (item.command_id,),
        )
        for item in validate_effect_order(contract, proposal.ordered_command_ids)
    ]


def _known_safety_findings(
    contract: MikroTikScriptContract,
    proposal: MikroTikOrderingProposal,
) -> list[MikroTikSemanticFinding]:
    """Compatibility checks retained while the explicit effect registry expands."""

    findings: list[MikroTikSemanticFinding] = []
    position = {cid: index for index, cid in enumerate(proposal.ordered_command_ids)}
    ids = set(position)

    def before(a: str, b: str, *, code: str, message: str) -> None:
        if a in ids and b in ids and position[a] >= position[b]:
            findings.append(MikroTikSemanticFinding(code, message, (a, b)))

    wg_interface = sorted(cid for cid in ids if cid.startswith("wireguard.10.interface"))
    wg_addresses = sorted(cid for cid in ids if cid.startswith("wireguard.20.address."))
    wg_peers = sorted(cid for cid in ids if cid.startswith("wireguard.30.peer."))
    wg_routes = sorted(cid for cid in ids if cid.startswith("wireguard.40.route."))
    for interface_id in wg_interface:
        for dependent in (*wg_addresses, *wg_peers, *wg_routes):
            before(
                interface_id,
                dependent,
                code="wireguard_interface_dependency",
                message="WireGuard interface must be established before address/peer/route primitives",
            )
    for address_id in wg_addresses:
        for dependent in (*wg_peers, *wg_routes):
            before(
                address_id,
                dependent,
                code="wireguard_address_dependency",
                message="WireGuard addressing must be established before peer/route primitives",
            )
    for peer_id in wg_peers:
        for route_id in wg_routes:
            before(
                peer_id,
                route_id,
                code="wireguard_peer_route_dependency",
                message="WireGuard peer scope must be established before dependent routes",
            )

    stage = next((cid for cid in ids if "stage-guard" in cid and "remove" not in cid and "release" not in cid), None)
    release = next((cid for cid in ids if "stage-guard" in cid and ("remove" in cid or "release" in cid)), None)
    managed_firewall = sorted(cid for cid in ids if cid.startswith("firewall."))
    if stage:
        for cid in managed_firewall:
            if cid != stage:
                before(
                    stage,
                    cid,
                    code="firewall_guard_dependency",
                    message="temporary fail-closed firewall guard must be installed before managed firewall mutation",
                )
    if release:
        for cid in managed_firewall:
            if cid != release:
                before(
                    cid,
                    release,
                    code="firewall_guard_release_dependency",
                    message="temporary firewall guard may be removed only after managed firewall construction",
                )

    vlan_enable = next(
        (
            cid
            for cid in ids
            if cid.startswith("vlan.")
            and ("activate-filtering" in cid or "enable-filter" in cid or "vlan-filtering" in cid)
        ),
        None,
    )
    if vlan_enable:
        for cid in sorted(item for item in ids if item.startswith("vlan.") and item != vlan_enable):
            before(
                cid,
                vlan_enable,
                code="vlan_filtering_dependency",
                message="VLAN membership/management preparation must precede bridge vlan-filtering enablement",
            )
    return findings


def attest_semantics(
    *,
    contract: MikroTikScriptContract,
    proposal: MikroTikOrderingProposal,
    script: MikroTikScriptArtifact,
) -> MikroTikSemanticAttestation:
    """Deterministically attest that model ordering did not create contradictions.

    Validation combines the immutable renderer order, the MikroTik resource/effect
    graph, and compatibility safety checks. The AI model never judges its own
    safety or supplies PASS evidence.
    """

    try:
        validate_ordering(contract, proposal)
    except MikroTikScriptPlanError as exc:
        findings = (
            MikroTikSemanticFinding("base_dependency_violation", str(exc), tuple(proposal.ordered_command_ids)),
        )
        return MikroTikSemanticAttestation(
            contract.render_sha256,
            script.script_sha256,
            script.ordered_command_ids,
            False,
            findings,
        )

    findings = [
        *_section_order_findings(contract, proposal),
        *_effect_graph_findings(contract, proposal),
        *_known_safety_findings(contract, proposal),
    ]
    if script.render_sha256 != contract.render_sha256:
        findings.append(
            MikroTikSemanticFinding(
                "render_digest_mismatch",
                "compiled script references a different deterministic render plan",
                script.ordered_command_ids,
            )
        )
    if script.ordered_command_ids != proposal.ordered_command_ids:
        findings.append(
            MikroTikSemanticFinding(
                "script_order_mismatch",
                "compiled script command order differs from the validated ordering proposal",
                script.ordered_command_ids,
            )
        )
    return MikroTikSemanticAttestation(
        render_sha256=contract.render_sha256,
        script_sha256=script.script_sha256,
        ordered_command_ids=script.ordered_command_ids,
        passed=not findings,
        findings=tuple(findings),
    )
