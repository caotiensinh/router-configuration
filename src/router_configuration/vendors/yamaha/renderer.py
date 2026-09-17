"""Deterministic Yamaha RTX3510 candidate renderer.

Y04 renders a deliberately tiny source-bound subset for review and dry-run
inspection only. It has no transport, apply, save, or production-write path.
"""

from __future__ import annotations

from dataclasses import dataclass
import hashlib
import ipaddress
import json
import re
from typing import Iterable, Mapping

from .knowledge import YamahaOfflineKnowledge


YAMAHA_RENDER_PLAN_SCHEMA = "yamaha-rtx3510-render-plan/1"
_ALLOWED_INTERFACES = frozenset({"lan1", "lan2", "lan3", "lan4"})
_SOURCE_IDS = ("YAMAHA-RTX-CMDREF", "YAMAHA-RTX3510-USERGUIDE")


class YamahaRenderError(ValueError):
    """Raised when a Yamaha candidate plan is outside the verified safe subset."""


@dataclass(frozen=True)
class YamahaStaticRouteIntent:
    destination: str
    gateway: str


def _interface_address_command(interface: str, address: str) -> str:
    normalized_interface = interface.strip().lower()
    if normalized_interface not in _ALLOWED_INTERFACES:
        raise YamahaRenderError(f"unsupported Yamaha interface: {interface}")
    if any(token in address for token in ("\n", "\r", ";", "|")):
        raise YamahaRenderError("unsafe Yamaha interface-address input")
    try:
        parsed = ipaddress.ip_interface(address)
    except ValueError as exc:
        raise YamahaRenderError(f"invalid Yamaha interface address: {address}") from exc
    if parsed.version != 4 or "/" not in address:
        raise YamahaRenderError("Y04 supports explicit-prefix IPv4 interface addresses only")
    return f"ip {normalized_interface} address {parsed.ip}/{parsed.network.prefixlen}"


def _static_route_command(intent: YamahaStaticRouteIntent) -> str:
    destination = intent.destination.strip()
    gateway = intent.gateway.strip()
    for value in (destination, gateway):
        if any(token in value for token in ("\n", "\r", ";", "|")):
            raise YamahaRenderError("unsafe Yamaha static-route input")

    if destination != "default":
        try:
            network = ipaddress.ip_network(destination, strict=True)
        except ValueError as exc:
            raise YamahaRenderError(
                f"invalid Yamaha static-route destination: {destination}"
            ) from exc
        if network.version != 4:
            raise YamahaRenderError("Y04 supports IPv4 static routes only")
        destination = str(network)

    try:
        gateway_ip = ipaddress.ip_address(gateway)
    except ValueError as exc:
        raise YamahaRenderError(
            f"Y04 supports IPv4-address gateways only: {gateway}"
        ) from exc
    if gateway_ip.version != 4:
        raise YamahaRenderError("Y04 supports IPv4-address gateways only")

    return f"ip route {destination} gateway {gateway_ip}"


def _validate_rendered_command(command: str) -> None:
    if any(token in command for token in ("\n", "\r", ";", "|")):
        raise YamahaRenderError("unsafe Yamaha rendered command")
    parts = command.split()
    if len(parts) == 4 and parts[0] == "ip" and parts[2] == "address":
        expected = _interface_address_command(parts[1], parts[3])
        if command != expected:
            raise YamahaRenderError(f"non-canonical Yamaha address command: {command}")
        return
    if len(parts) == 5 and parts[:2] == ["ip", "route"] and parts[3] == "gateway":
        expected = _static_route_command(
            YamahaStaticRouteIntent(destination=parts[2], gateway=parts[4])
        )
        if command != expected:
            raise YamahaRenderError(f"non-canonical Yamaha route command: {command}")
        return
    raise YamahaRenderError(f"unapproved Yamaha Y04 command: {command}")


def render_candidate_plan(
    *,
    interface_addresses: Mapping[str, str] | None = None,
    static_routes: Iterable[YamahaStaticRouteIntent] = (),
) -> dict:
    """Render a deterministic non-executable Yamaha candidate configuration."""

    address_commands: list[str] = []
    seen_interfaces: set[str] = set()
    for interface, address in (interface_addresses or {}).items():
        normalized = interface.strip().lower()
        if normalized in seen_interfaces:
            raise YamahaRenderError(f"duplicate Yamaha interface intent: {interface}")
        seen_interfaces.add(normalized)
        address_commands.append(_interface_address_command(interface, address))

    route_commands: list[str] = []
    seen_destinations: set[str] = set()
    for intent in static_routes:
        if not isinstance(intent, YamahaStaticRouteIntent):
            raise YamahaRenderError("static_routes must contain YamahaStaticRouteIntent")
        command = _static_route_command(intent)
        destination = command.split()[2]
        if destination in seen_destinations:
            raise YamahaRenderError(
                f"Y04 allows one gateway per route destination: {destination}"
            )
        seen_destinations.add(destination)
        route_commands.append(command)

    commands = tuple(sorted(address_commands) + sorted(route_commands))
    if not commands:
        raise YamahaRenderError("Yamaha candidate plan must contain at least one operation")

    knowledge = YamahaOfflineKnowledge()
    missing_sources = sorted(set(_SOURCE_IDS) - set(knowledge.source_ids()))
    if missing_sources:
        raise YamahaRenderError(
            "Yamaha renderer source binding is incomplete: " + ", ".join(missing_sources)
        )

    plan = {
        "schema_version": YAMAHA_RENDER_PLAN_SCHEMA,
        "vendor": "Yamaha",
        "model": "RTX3510",
        "firmware": "23.01.03",
        "commands": list(commands),
        "documentation_source_ids": list(_SOURCE_IDS),
        "knowledge_sha256": knowledge.digest_sha256,
        "mode": "candidate_dry_run_only",
        "requires_current_state": True,
        "requires_prechange_backup": True,
        "requires_human_approval": True,
        "requires_postchange_verification": True,
        "rollback_strategy": "restore_verified_prechange_state",
        "transport_authorized": False,
        "apply_authorized": False,
        "save_authorized": False,
        "production_write_authorized": False,
        "physical_device_verified": False,
    }
    canonical = json.dumps(plan, sort_keys=True, separators=(",", ":"))
    plan["plan_sha256"] = hashlib.sha256(canonical.encode("utf-8")).hexdigest()
    validate_candidate_plan(plan)
    return plan


def validate_candidate_plan(plan: Mapping[str, object]) -> None:
    if plan.get("schema_version") != YAMAHA_RENDER_PLAN_SCHEMA:
        raise YamahaRenderError("unsupported Yamaha render-plan schema")
    if (
        plan.get("vendor") != "Yamaha"
        or plan.get("model") != "RTX3510"
        or plan.get("firmware") != "23.01.03"
    ):
        raise YamahaRenderError("Yamaha render-plan identity mismatch")
    if plan.get("mode") != "candidate_dry_run_only":
        raise YamahaRenderError("Yamaha Y04 plan must remain dry-run only")

    for key in (
        "transport_authorized",
        "apply_authorized",
        "save_authorized",
        "production_write_authorized",
        "physical_device_verified",
    ):
        if plan.get(key) is not False:
            raise YamahaRenderError(f"Yamaha render plan overclaims {key}")
    for key in (
        "requires_current_state",
        "requires_prechange_backup",
        "requires_human_approval",
        "requires_postchange_verification",
    ):
        if plan.get(key) is not True:
            raise YamahaRenderError(f"Yamaha render safety requirement removed: {key}")
    if plan.get("rollback_strategy") != "restore_verified_prechange_state":
        raise YamahaRenderError("Yamaha rollback requirement was weakened")

    sources = plan.get("documentation_source_ids")
    if sources != list(_SOURCE_IDS):
        raise YamahaRenderError("Yamaha render-plan source binding mismatch")
    knowledge_digest = plan.get("knowledge_sha256")
    if not isinstance(knowledge_digest, str) or re.fullmatch(r"[0-9a-f]{64}", knowledge_digest) is None:
        raise YamahaRenderError("invalid Yamaha renderer knowledge digest")

    commands = plan.get("commands")
    if not isinstance(commands, list) or not commands:
        raise YamahaRenderError("Yamaha render plan contains no commands")
    if not all(isinstance(command, str) for command in commands):
        raise YamahaRenderError("invalid Yamaha rendered command")
    if commands != sorted(commands):
        raise YamahaRenderError("Yamaha render plan must be deterministic")
    for command in commands:
        _validate_rendered_command(command)

    supplied_digest = plan.get("plan_sha256")
    if not isinstance(supplied_digest, str) or re.fullmatch(r"[0-9a-f]{64}", supplied_digest) is None:
        raise YamahaRenderError("invalid Yamaha plan digest")
    payload = dict(plan)
    payload.pop("plan_sha256", None)
    canonical = json.dumps(payload, sort_keys=True, separators=(",", ":"))
    expected = hashlib.sha256(canonical.encode("utf-8")).hexdigest()
    if supplied_digest != expected:
        raise YamahaRenderError("Yamaha render-plan digest mismatch")
