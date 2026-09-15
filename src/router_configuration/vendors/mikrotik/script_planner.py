from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass
from typing import Any, Iterable, Mapping

from .inference import MikroTikReasoningProvider, MikroTikReasoningRequest
from .knowledge import MikroTikOfflineKnowledge


class MikroTikScriptPlanError(ValueError):
    pass


_SCRIPT_NAME = re.compile(r"^[A-Za-z0-9_.-]{1,96}$")
_ALLOWED_AI_KEYS = {"ordered_command_ids", "rationale", "knowledge_ids"}


@dataclass(frozen=True)
class MikroTikCommandPrimitive:
    command_id: str
    section: str
    command: str
    risk: int
    subsystem: str
    source_index: int

    def model_view(self) -> dict[str, Any]:
        """Metadata intentionally excludes the RouterOS command text."""
        return {
            "command_id": self.command_id,
            "section": self.section,
            "risk": self.risk,
            "subsystem": self.subsystem,
            "source_index": self.source_index,
        }


@dataclass(frozen=True)
class MikroTikDependency:
    before: str
    after: str
    reason: str

    def as_dict(self) -> dict[str, str]:
        return {"before": self.before, "after": self.after, "reason": self.reason}


@dataclass(frozen=True)
class MikroTikScriptContract:
    routeros_version: str
    render_sha256: str
    commands: tuple[MikroTikCommandPrimitive, ...]
    dependencies: tuple[MikroTikDependency, ...]
    knowledge_ids: tuple[str, ...]

    def model_payload(self) -> dict[str, Any]:
        """Return the only configuration surface a reasoning model may see."""
        return {
            "schema_version": "mikrotik-script-order-contract/1",
            "routeros_version": self.routeros_version,
            "render_sha256": self.render_sha256,
            "commands": [item.model_view() for item in self.commands],
            "dependencies": [item.as_dict() for item in self.dependencies],
            "knowledge_ids": list(self.knowledge_ids),
            "model_authority": "ordering_only",
            "raw_routeros_cli_present": False,
        }


@dataclass(frozen=True)
class MikroTikOrderingProposal:
    ordered_command_ids: tuple[str, ...]
    rationale: str
    knowledge_ids: tuple[str, ...]
    source: str


@dataclass(frozen=True)
class MikroTikScriptArtifact:
    file_name: str
    script: str
    script_sha256: str
    render_sha256: str
    ordered_command_ids: tuple[str, ...]
    dry_run_command: str
    dry_run_required: bool = True
    write_authorized: bool = False

    def as_dict(self) -> dict[str, Any]:
        return {
            "schema_version": "mikrotik-rsc-artifact/1",
            "file_name": self.file_name,
            "script": self.script,
            "script_sha256": self.script_sha256,
            "render_sha256": self.render_sha256,
            "ordered_command_ids": list(self.ordered_command_ids),
            "dry_run_command": self.dry_run_command,
            "dry_run_required": self.dry_run_required,
            "write_authorized": self.write_authorized,
        }


def _subsystem(command_id: str) -> str:
    return command_id.split(".", 1)[0].strip().lower() or "unknown"


def _extract_commands(render_plan: Mapping[str, Any]) -> tuple[MikroTikCommandPrimitive, ...]:
    if render_plan.get("transport_present") is True or render_plan.get("write_authorized") is True:
        raise MikroTikScriptPlanError("script planning accepts generation-only render plans")
    if render_plan.get("complete") is False:
        raise MikroTikScriptPlanError("incomplete render plans cannot become executable scripts")
    blockers = render_plan.get("blocked_operations", [])
    if blockers not in (None, []):
        raise MikroTikScriptPlanError("render plan still contains blocked operations")

    raw = render_plan.get("commands")
    if not isinstance(raw, list) or not raw:
        raise MikroTikScriptPlanError("render plan requires a non-empty commands list")

    commands: list[MikroTikCommandPrimitive] = []
    ids: set[str] = set()
    command_texts: set[str] = set()
    for index, item in enumerate(raw):
        if not isinstance(item, Mapping):
            raise MikroTikScriptPlanError(f"commands[{index}] must be an object")
        command_id = str(item.get("command_id") or "").strip()
        section = str(item.get("section") or "").strip()
        command = str(item.get("command") or "").strip()
        risk = item.get("risk", 30)
        if not command_id or not section or not command:
            raise MikroTikScriptPlanError(f"commands[{index}] requires command_id/section/command")
        if command_id in ids:
            raise MikroTikScriptPlanError(f"duplicate command_id: {command_id}")
        if command in command_texts:
            raise MikroTikScriptPlanError("duplicate immutable RouterOS command text detected")
        if isinstance(risk, bool) or not isinstance(risk, int) or risk < 0:
            raise MikroTikScriptPlanError(f"invalid risk for {command_id}")
        ids.add(command_id)
        command_texts.add(command)
        commands.append(
            MikroTikCommandPrimitive(
                command_id=command_id,
                section=section,
                command=command,
                risk=risk,
                subsystem=_subsystem(command_id),
                source_index=index,
            )
        )
    return tuple(commands)


def _renderer_dependencies(
    commands: tuple[MikroTikCommandPrimitive, ...],
) -> list[MikroTikDependency]:
    """Preserve the renderer's order inside each subsystem.

    AI may interleave independent subsystems, but it cannot reverse ordering that
    a deterministic RouterOS renderer already established.
    """
    groups: dict[str, list[MikroTikCommandPrimitive]] = {}
    for item in commands:
        groups.setdefault(item.subsystem, []).append(item)

    edges: list[MikroTikDependency] = []
    for subsystem, items in sorted(groups.items()):
        ordered = sorted(items, key=lambda item: item.source_index)
        for before, after in zip(ordered, ordered[1:]):
            edges.append(
                MikroTikDependency(
                    before.command_id,
                    after.command_id,
                    f"preserve deterministic {subsystem} renderer order",
                )
            )
    return edges


def _safety_dependencies(
    commands: tuple[MikroTikCommandPrimitive, ...],
) -> list[MikroTikDependency]:
    ids = {item.command_id for item in commands}
    sorted_ids = sorted(ids)
    edges: list[MikroTikDependency] = []

    stage = next(
        (
            cid
            for cid in sorted_ids
            if "stage-guard" in cid and "remove" not in cid and "release" not in cid
        ),
        None,
    )
    release = next(
        (
            cid
            for cid in sorted_ids
            if "stage-guard" in cid and ("remove" in cid or "release" in cid)
        ),
        None,
    )
    firewall_ids = sorted(cid for cid in ids if cid.startswith("firewall."))
    if stage:
        for cid in firewall_ids:
            if cid != stage:
                edges.append(MikroTikDependency(stage, cid, "fail-closed firewall guard must exist first"))
    if release:
        for cid in firewall_ids:
            if cid != release:
                edges.append(MikroTikDependency(cid, release, "firewall guard is removed only after policy is built"))

    vlan_enable = next(
        (
            cid
            for cid in sorted_ids
            if cid.startswith("vlan.") and ("enable-filter" in cid or "vlan-filtering" in cid)
        ),
        None,
    )
    if vlan_enable:
        for cid in sorted(cid for cid in ids if cid.startswith("vlan.") and cid != vlan_enable):
            edges.append(
                MikroTikDependency(cid, vlan_enable, "bridge VLAN filtering is enabled after VLAN preparation")
            )
    return edges


def _dedupe_dependencies(edges: Iterable[MikroTikDependency]) -> tuple[MikroTikDependency, ...]:
    seen: set[tuple[str, str]] = set()
    result: list[MikroTikDependency] = []
    for edge in edges:
        key = (edge.before, edge.after)
        if edge.before == edge.after or key in seen:
            continue
        seen.add(key)
        result.append(edge)
    result.sort(key=lambda item: (item.before, item.after, item.reason))
    return tuple(result)


def build_script_contract(
    *,
    render_plan: Mapping[str, Any],
    routeros_version: str,
    knowledge: MikroTikOfflineKnowledge | None = None,
) -> MikroTikScriptContract:
    version = routeros_version.strip()
    if not version:
        raise MikroTikScriptPlanError("RouterOS version is required before script planning")
    render_sha256 = str(render_plan.get("render_sha256") or "").strip()
    if not render_sha256:
        raise MikroTikScriptPlanError("render plan must include render_sha256")

    store = knowledge or MikroTikOfflineKnowledge.bundled()
    mandatory = ["cli-reference", "scripting-import-validation", "configuration-management"]
    commands = _extract_commands(render_plan)
    if any(item.subsystem == "firewall" for item in commands):
        mandatory.append("firewall-stateful")
    if any(item.subsystem == "vlan" for item in commands):
        mandatory.append("bridge-vlan")
    for record_id in mandatory:
        store.get(record_id)

    dependencies = _dedupe_dependencies(
        [*_renderer_dependencies(commands), *_safety_dependencies(commands)]
    )
    return MikroTikScriptContract(
        routeros_version=version,
        render_sha256=render_sha256,
        commands=commands,
        dependencies=dependencies,
        knowledge_ids=tuple(mandatory),
    )


def deterministic_order(contract: MikroTikScriptContract) -> MikroTikOrderingProposal:
    """Stable topological ordering for offline/no-model operation."""
    ids = {item.command_id for item in contract.commands}
    indegree = {cid: 0 for cid in ids}
    outgoing: dict[str, set[str]] = {cid: set() for cid in ids}
    for edge in contract.dependencies:
        if edge.before not in ids or edge.after not in ids:
            raise MikroTikScriptPlanError("dependency references an unknown command")
        if edge.after not in outgoing[edge.before]:
            outgoing[edge.before].add(edge.after)
            indegree[edge.after] += 1

    source_index = {item.command_id: item.source_index for item in contract.commands}
    ready = sorted((cid for cid, degree in indegree.items() if degree == 0), key=lambda cid: (source_index[cid], cid))
    ordered: list[str] = []
    while ready:
        current = ready.pop(0)
        ordered.append(current)
        for target in sorted(outgoing[current], key=lambda cid: (source_index[cid], cid)):
            indegree[target] -= 1
            if indegree[target] == 0:
                ready.append(target)
                ready.sort(key=lambda cid: (source_index[cid], cid))
    if len(ordered) != len(ids):
        raise MikroTikScriptPlanError("command dependency graph contains a cycle")
    return MikroTikOrderingProposal(tuple(ordered), "deterministic topological order", contract.knowledge_ids, "deterministic")


def _strip_json_fence(text: str) -> str:
    value = text.strip()
    if value.startswith("```"):
        lines = value.splitlines()
        if lines and lines[0].startswith("```"):
            lines = lines[1:]
        if lines and lines[-1].strip() == "```":
            lines = lines[:-1]
        value = "\n".join(lines).strip()
    return value


def parse_ai_ordering(text: str, contract: MikroTikScriptContract) -> MikroTikOrderingProposal:
    try:
        payload = json.loads(_strip_json_fence(text))
    except json.JSONDecodeError as exc:
        raise MikroTikScriptPlanError("AI ordering response must be a single JSON object") from exc
    if not isinstance(payload, Mapping):
        raise MikroTikScriptPlanError("AI ordering response must be an object")
    unknown = sorted(set(payload) - _ALLOWED_AI_KEYS)
    if unknown:
        raise MikroTikScriptPlanError(
            "AI ordering response contains forbidden fields: " + ", ".join(unknown)
        )
    raw_ids = payload.get("ordered_command_ids")
    if not isinstance(raw_ids, list) or not all(isinstance(item, str) for item in raw_ids):
        raise MikroTikScriptPlanError("ordered_command_ids must be a list of command IDs")
    raw_knowledge = payload.get("knowledge_ids", list(contract.knowledge_ids))
    if not isinstance(raw_knowledge, list) or not all(isinstance(item, str) for item in raw_knowledge):
        raise MikroTikScriptPlanError("knowledge_ids must be a list of record IDs")
    proposal = MikroTikOrderingProposal(
        tuple(raw_ids),
        str(payload.get("rationale") or "").strip(),
        tuple(raw_knowledge),
        "ai",
    )
    validate_ordering(contract, proposal)
    return proposal


def validate_ordering(
    contract: MikroTikScriptContract,
    proposal: MikroTikOrderingProposal,
) -> None:
    expected = [item.command_id for item in contract.commands]
    ordered = list(proposal.ordered_command_ids)
    if len(ordered) != len(set(ordered)):
        raise MikroTikScriptPlanError("ordering contains duplicate command IDs")
    missing = sorted(set(expected) - set(ordered))
    unknown = sorted(set(ordered) - set(expected))
    if missing or unknown:
        raise MikroTikScriptPlanError(
            f"ordering must contain exactly the immutable renderer command set; missing={missing}, unknown={unknown}"
        )
    allowed_knowledge = set(contract.knowledge_ids)
    if not set(proposal.knowledge_ids).issubset(allowed_knowledge):
        raise MikroTikScriptPlanError("ordering references knowledge outside the validated contract")

    position = {cid: index for index, cid in enumerate(ordered)}
    violated = [edge for edge in contract.dependencies if position[edge.before] >= position[edge.after]]
    if violated:
        detail = "; ".join(f"{edge.before} -> {edge.after}: {edge.reason}" for edge in violated[:8])
        raise MikroTikScriptPlanError("ordering violates command dependencies: " + detail)


def build_ordering_reasoning_request(contract: MikroTikScriptContract) -> MikroTikReasoningRequest:
    return MikroTikReasoningRequest(
        task=(
            "Order the supplied immutable MikroTik command IDs into one safe transaction. "
            "Return ONLY JSON with ordered_command_ids, rationale, and knowledge_ids. "
            "Do not output RouterOS CLI, do not create/delete/change command IDs, and do not invent values."
        ),
        evidence=contract.model_payload(),
        constraints=(
            "The command text is intentionally unavailable to you; syntax belongs to deterministic RouterOS renderers.",
            "Every command ID must appear exactly once.",
            "Every dependency edge before -> after is mandatory.",
            "Prefer minimal risk ordering among independent commands, but never override dependencies.",
        ),
        knowledge_limit=8,
    )


def propose_order_with_ai(
    *,
    provider: MikroTikReasoningProvider,
    contract: MikroTikScriptContract,
) -> MikroTikOrderingProposal:
    result = provider.reason(build_ordering_reasoning_request(contract))
    return parse_ai_ordering(result.text, contract)


def compile_script(
    *,
    contract: MikroTikScriptContract,
    proposal: MikroTikOrderingProposal,
    file_name: str,
) -> MikroTikScriptArtifact:
    validate_ordering(contract, proposal)
    name = file_name.strip()
    if not _SCRIPT_NAME.fullmatch(name):
        raise MikroTikScriptPlanError("file_name must use only letters, digits, dot, underscore, or hyphen")
    if not name.endswith(".rsc"):
        name += ".rsc"

    by_id = {item.command_id: item for item in contract.commands}
    lines = [
        "# router-configuration generated MikroTik RouterOS script",
        f"# RouterOS target: {contract.routeros_version}",
        f"# render_sha256: {contract.render_sha256}",
        f"# ordering_source: {proposal.source}",
        "# AI is not a syntax authority; commands below are immutable renderer output.",
        "",
    ]
    for cid in proposal.ordered_command_ids:
        primitive = by_id[cid]
        lines.append(f"# command_id={cid} section={primitive.section} risk={primitive.risk}")
        lines.append(primitive.command)
    script = "\n".join(lines).rstrip() + "\n"
    digest = hashlib.sha256(script.encode("utf-8")).hexdigest()
    dry_run = f'/import file-name="{name}" verbose=yes dry-run'
    return MikroTikScriptArtifact(
        file_name=name,
        script=script,
        script_sha256=digest,
        render_sha256=contract.render_sha256,
        ordered_command_ids=proposal.ordered_command_ids,
        dry_run_command=dry_run,
    )
