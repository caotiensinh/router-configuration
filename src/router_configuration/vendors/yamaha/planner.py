"""Fail-closed Yamaha RTX3510 current-state to desired-state planning.

Y05 consumes the conservative Y03 normalized state and the bounded Y04
renderer. It plans only operations that can be proven safe from those contracts.
It never infers deletions and never authorizes execution.
"""

from __future__ import annotations

import hashlib
import json
import re
from typing import Iterable, Mapping

from .normalized import validate_normalized_state
from .renderer import (
    YamahaRenderError,
    YamahaStaticRouteIntent,
    render_candidate_plan,
    validate_candidate_plan,
)


YAMAHA_CHANGE_PLAN_SCHEMA = "yamaha-rtx3510-change-plan/1"


class YamahaChangePlanError(ValueError):
    """Raised when a Yamaha change plan cannot be derived safely."""


def _canonical_required_routes(
    required_static_routes: Iterable[YamahaStaticRouteIntent],
) -> tuple[tuple[str, str], ...]:
    intents = tuple(required_static_routes)
    if not intents:
        return ()
    try:
        rendered = render_candidate_plan(static_routes=intents)
    except YamahaRenderError as exc:
        raise YamahaChangePlanError(str(exc)) from exc

    routes: list[tuple[str, str]] = []
    for command in rendered["commands"]:
        parts = command.split()
        if len(parts) != 5 or parts[:2] != ["ip", "route"] or parts[3] != "gateway":
            raise YamahaChangePlanError("unexpected non-route command in route intent")
        routes.append((parts[2], parts[4]))
    return tuple(routes)


def _canonical_interface_requests(
    interface_addresses: Mapping[str, str] | None,
) -> tuple[tuple[str, str], ...]:
    if not interface_addresses:
        return ()
    try:
        rendered = render_candidate_plan(interface_addresses=interface_addresses)
    except YamahaRenderError as exc:
        raise YamahaChangePlanError(str(exc)) from exc

    requests: list[tuple[str, str]] = []
    for command in rendered["commands"]:
        parts = command.split()
        if len(parts) != 4 or parts[0] != "ip" or parts[2] != "address":
            raise YamahaChangePlanError("unexpected non-interface command in interface intent")
        requests.append((parts[1], parts[3]))
    return tuple(requests)


def _route_observation(route: Mapping[str, object]) -> dict[str, object]:
    return {
        "gateway": route.get("gateway"),
        "interface": route.get("interface"),
        "route_type": route.get("route_type"),
    }


def _is_static(route: Mapping[str, object]) -> bool:
    return str(route.get("route_type", "")).strip().casefold() == "static"


def _expected_blockers(
    route_actions: list[object],
    interface_actions: list[object],
) -> list[dict[str, object]]:
    expected: list[dict[str, object]] = []
    for action in route_actions:
        if not isinstance(action, Mapping) or action.get("status") != "BLOCKED":
            continue
        expected.append(
            {
                "surface": "static_route",
                "destination": action.get("destination"),
                "requested_gateway": action.get("gateway"),
                "code": action.get("blocker_code"),
                "current": action.get("current"),
            }
        )
    for action in interface_actions:
        if not isinstance(action, Mapping):
            continue
        expected.append(
            {
                "surface": "interface_address",
                "interface": action.get("interface"),
                "requested_address": action.get("address"),
                "code": "CURRENT_INTERFACE_ADDRESS_UNAVAILABLE",
            }
        )
    return expected


def build_change_plan(
    *,
    current_state: Mapping[str, object],
    required_static_routes: Iterable[YamahaStaticRouteIntent] = (),
    interface_addresses: Mapping[str, str] | None = None,
) -> dict:
    """Build a deterministic non-executable change plan.

    `required_static_routes` is additive requirement scope. Unmentioned current
    routes are not deletion requests.
    """

    try:
        validate_normalized_state(current_state)
    except Exception as exc:
        raise YamahaChangePlanError(f"invalid Yamaha current state: {exc}") from exc

    required_routes = _canonical_required_routes(required_static_routes)
    interface_requests = _canonical_interface_requests(interface_addresses)

    current_by_destination: dict[str, list[Mapping[str, object]]] = {}
    raw_routes = current_state.get("ipv4_routes")
    if not isinstance(raw_routes, list):
        raise YamahaChangePlanError("Yamaha current routes are missing")
    for route in raw_routes:
        if not isinstance(route, Mapping):
            raise YamahaChangePlanError("invalid Yamaha current route record")
        destination = str(route.get("destination", ""))
        current_by_destination.setdefault(destination, []).append(route)

    route_actions: list[dict[str, object]] = []
    additions: list[YamahaStaticRouteIntent] = []
    for destination, gateway in required_routes:
        observed = current_by_destination.get(destination, [])
        if not observed:
            route_actions.append(
                {
                    "destination": destination,
                    "gateway": gateway,
                    "status": "ADD",
                    "current": [],
                }
            )
            additions.append(YamahaStaticRouteIntent(destination, gateway))
            continue

        current_observations = [_route_observation(route) for route in observed]
        matching = [route for route in observed if route.get("gateway") == gateway]
        matching_static = [route for route in matching if _is_static(route)]

        if len(observed) == 1 and len(matching_static) == 1:
            route_actions.append(
                {
                    "destination": destination,
                    "gateway": gateway,
                    "status": "PRESENT",
                    "current": current_observations,
                }
            )
            continue

        if len(observed) == 1 and matching and not matching_static:
            blocker_code = "NON_STATIC_CURRENT_ROUTE"
        elif matching:
            blocker_code = "AMBIGUOUS_CURRENT_ROUTE"
        else:
            blocker_code = "ROUTE_DESTINATION_CONFLICT"
        route_actions.append(
            {
                "destination": destination,
                "gateway": gateway,
                "status": "BLOCKED",
                "blocker_code": blocker_code,
                "current": current_observations,
            }
        )

    interface_actions: list[dict[str, object]] = []
    for interface, address in interface_requests:
        interface_actions.append(
            {
                "interface": interface,
                "address": address,
                "status": "BLOCKED",
                "blocker_code": "CURRENT_INTERFACE_ADDRESS_UNAVAILABLE",
            }
        )

    blockers = _expected_blockers(route_actions, interface_actions)
    candidate_render_plan = None
    if additions:
        candidate_render_plan = render_candidate_plan(static_routes=tuple(additions))

    if blockers:
        status = "BLOCKED"
    elif additions:
        status = "CANDIDATE_READY_FOR_REVIEW"
    else:
        status = "NO_CHANGE_REQUIRED"

    source = current_state.get("source")
    if not isinstance(source, Mapping):
        raise YamahaChangePlanError("Yamaha current-state source metadata is missing")

    plan = {
        "schema_version": YAMAHA_CHANGE_PLAN_SCHEMA,
        "vendor": "Yamaha",
        "model": "RTX3510",
        "firmware": "23.01.03",
        "current_state_sha256": current_state.get("record_sha256"),
        "current_state_capture_source": source.get("capture_source"),
        "required_static_routes": [
            {"destination": destination, "gateway": gateway}
            for destination, gateway in required_routes
        ],
        "requested_interface_addresses": [
            {"interface": interface, "address": address}
            for interface, address in interface_requests
        ],
        "route_actions": route_actions,
        "interface_actions": interface_actions,
        "blockers": blockers,
        "candidate_render_plan": candidate_render_plan,
        "deletion_semantics": "not_inferred_additive_requirement_scope",
        "removal_commands": [],
        "status": status,
        "review_ready": status == "CANDIDATE_READY_FOR_REVIEW",
        "approval_ready": False,
        "execution_ready": False,
        "requires_human_approval": bool(additions),
        "live_device_verified": False,
        "physical_device_verified": False,
        "transport_authorized": False,
        "apply_authorized": False,
        "save_authorized": False,
        "production_write_authorized": False,
    }
    canonical = json.dumps(plan, sort_keys=True, separators=(",", ":"))
    plan["plan_sha256"] = hashlib.sha256(canonical.encode("utf-8")).hexdigest()
    validate_change_plan(plan)
    return plan


def validate_change_plan(plan: Mapping[str, object]) -> None:
    if plan.get("schema_version") != YAMAHA_CHANGE_PLAN_SCHEMA:
        raise YamahaChangePlanError("unsupported Yamaha change-plan schema")
    if (
        plan.get("vendor") != "Yamaha"
        or plan.get("model") != "RTX3510"
        or plan.get("firmware") != "23.01.03"
    ):
        raise YamahaChangePlanError("Yamaha change-plan identity mismatch")

    current_digest = plan.get("current_state_sha256")
    if not isinstance(current_digest, str) or re.fullmatch(r"[0-9a-f]{64}", current_digest) is None:
        raise YamahaChangePlanError("invalid Yamaha current-state digest")
    if plan.get("current_state_capture_source") != "caller_supplied":
        raise YamahaChangePlanError("Yamaha Y05 current-state provenance changed")

    for key in (
        "approval_ready",
        "execution_ready",
        "live_device_verified",
        "physical_device_verified",
        "transport_authorized",
        "apply_authorized",
        "save_authorized",
        "production_write_authorized",
    ):
        if plan.get(key) is not False:
            raise YamahaChangePlanError(f"Yamaha change plan overclaims {key}")

    if plan.get("deletion_semantics") != "not_inferred_additive_requirement_scope":
        raise YamahaChangePlanError("Yamaha Y05 deletion boundary was weakened")
    if plan.get("removal_commands") != []:
        raise YamahaChangePlanError("Yamaha Y05 must not generate removal commands")

    required_routes = plan.get("required_static_routes")
    route_actions = plan.get("route_actions")
    interface_requests = plan.get("requested_interface_addresses")
    interface_actions = plan.get("interface_actions")
    blockers = plan.get("blockers")
    if not isinstance(required_routes, list) or not isinstance(route_actions, list):
        raise YamahaChangePlanError("invalid Yamaha route-plan collections")
    if not isinstance(interface_requests, list) or not isinstance(interface_actions, list):
        raise YamahaChangePlanError("invalid Yamaha interface-plan collections")
    if not isinstance(blockers, list):
        raise YamahaChangePlanError("invalid Yamaha blocker collection")

    canonical_required: list[tuple[str, str]] = []
    for item in required_routes:
        if not isinstance(item, Mapping):
            raise YamahaChangePlanError("invalid Yamaha required route")
        destination = item.get("destination")
        gateway = item.get("gateway")
        if not isinstance(destination, str) or not isinstance(gateway, str):
            raise YamahaChangePlanError("invalid Yamaha required route values")
        canonical_required.append((destination, gateway))
    if canonical_required:
        expected_required = _canonical_required_routes(
            YamahaStaticRouteIntent(destination, gateway)
            for destination, gateway in canonical_required
        )
        if tuple(canonical_required) != expected_required:
            raise YamahaChangePlanError("non-canonical Yamaha required routes")

    route_action_keys: list[tuple[str, str]] = []
    addition_intents: list[YamahaStaticRouteIntent] = []
    for action in route_actions:
        if not isinstance(action, Mapping):
            raise YamahaChangePlanError("invalid Yamaha route action")
        destination = action.get("destination")
        gateway = action.get("gateway")
        status = action.get("status")
        current = action.get("current")
        if not isinstance(destination, str) or not isinstance(gateway, str):
            raise YamahaChangePlanError("invalid Yamaha route action values")
        if not isinstance(current, list) or not all(isinstance(item, Mapping) for item in current):
            raise YamahaChangePlanError("invalid Yamaha current-route evidence")
        if status not in {"ADD", "PRESENT", "BLOCKED"}:
            raise YamahaChangePlanError("invalid Yamaha route action status")
        route_action_keys.append((destination, gateway))
        if status == "ADD":
            if current or "blocker_code" in action:
                raise YamahaChangePlanError("Yamaha ADD route carries contradictory state")
            addition_intents.append(YamahaStaticRouteIntent(destination, gateway))
        elif status == "PRESENT":
            if (
                len(current) != 1
                or current[0].get("gateway") != gateway
                or not _is_static(current[0])
                or "blocker_code" in action
            ):
                raise YamahaChangePlanError("Yamaha PRESENT static route is inconsistent")
        else:
            if action.get("blocker_code") not in {
                "AMBIGUOUS_CURRENT_ROUTE",
                "ROUTE_DESTINATION_CONFLICT",
                "NON_STATIC_CURRENT_ROUTE",
            }:
                raise YamahaChangePlanError("invalid Yamaha route blocker")
            if not current:
                raise YamahaChangePlanError("blocked Yamaha route lacks current evidence")
    if route_action_keys != canonical_required:
        raise YamahaChangePlanError("Yamaha route actions do not match requirements")

    seen_interfaces: set[str] = set()
    for item in interface_requests:
        if not isinstance(item, Mapping):
            raise YamahaChangePlanError("invalid Yamaha interface request")
        interface = item.get("interface")
        address = item.get("address")
        if not isinstance(interface, str) or not isinstance(address, str):
            raise YamahaChangePlanError("invalid Yamaha interface request values")
        if interface in seen_interfaces:
            raise YamahaChangePlanError("duplicate Yamaha interface request")
        seen_interfaces.add(interface)
    if interface_requests:
        expected_requests = _canonical_interface_requests(
            {str(item["interface"]): str(item["address"]) for item in interface_requests}
        )
        actual_requests = [
            (str(item["interface"]), str(item["address"])) for item in interface_requests
        ]
        if actual_requests != list(expected_requests):
            raise YamahaChangePlanError("non-canonical Yamaha interface requests")

    if len(interface_actions) != len(interface_requests):
        raise YamahaChangePlanError("Yamaha interface actions do not match requests")
    for request, action in zip(interface_requests, interface_actions):
        if not isinstance(request, Mapping) or not isinstance(action, Mapping):
            raise YamahaChangePlanError("invalid Yamaha interface action")
        if action.get("interface") != request.get("interface") or action.get("address") != request.get("address"):
            raise YamahaChangePlanError("Yamaha interface action/request mismatch")
        if action.get("status") != "BLOCKED" or action.get("blocker_code") != "CURRENT_INTERFACE_ADDRESS_UNAVAILABLE":
            raise YamahaChangePlanError("Yamaha interface request must remain blocked")

    expected_blockers = _expected_blockers(route_actions, interface_actions)
    if blockers != expected_blockers:
        raise YamahaChangePlanError("Yamaha blocker evidence is inconsistent")

    candidate = plan.get("candidate_render_plan")
    if addition_intents:
        if not isinstance(candidate, Mapping):
            raise YamahaChangePlanError("Yamaha safe additions are missing candidate rendering")
        validate_candidate_plan(candidate)
        expected_candidate = render_candidate_plan(static_routes=tuple(addition_intents))
        if candidate != expected_candidate:
            raise YamahaChangePlanError("Yamaha candidate rendering does not match safe additions")
        if plan.get("requires_human_approval") is not True:
            raise YamahaChangePlanError("Yamaha candidate changes require human approval")
    else:
        if candidate is not None:
            raise YamahaChangePlanError("Yamaha candidate rendering exists without additions")
        if plan.get("requires_human_approval") is not False:
            raise YamahaChangePlanError("Yamaha no-change plan must not request approval")

    if blockers:
        expected_status = "BLOCKED"
    elif addition_intents:
        expected_status = "CANDIDATE_READY_FOR_REVIEW"
    else:
        expected_status = "NO_CHANGE_REQUIRED"
    if plan.get("status") != expected_status:
        raise YamahaChangePlanError("Yamaha change-plan status is inconsistent")
    if plan.get("review_ready") != (expected_status == "CANDIDATE_READY_FOR_REVIEW"):
        raise YamahaChangePlanError("Yamaha review-ready state is inconsistent")

    supplied_digest = plan.get("plan_sha256")
    if not isinstance(supplied_digest, str) or re.fullmatch(r"[0-9a-f]{64}", supplied_digest) is None:
        raise YamahaChangePlanError("invalid Yamaha change-plan digest")
    payload = dict(plan)
    payload.pop("plan_sha256", None)
    canonical = json.dumps(payload, sort_keys=True, separators=(",", ":"))
    expected_digest = hashlib.sha256(canonical.encode("utf-8")).hexdigest()
    if supplied_digest != expected_digest:
        raise YamahaChangePlanError("Yamaha change-plan digest mismatch")
