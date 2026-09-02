from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass
from typing import Any, Mapping


class PbrIntentError(ValueError):
    pass


_NAME = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,62}[A-Za-z0-9]$|^[A-Za-z0-9]$")


def _name(value: Any, label: str) -> str:
    text = str(value or "").strip()
    if not _NAME.fullmatch(text):
        raise PbrIntentError(f"{label} contains unsupported characters")
    return text


def _network(value: Any, label: str, *, bounded: bool) -> str:
    try:
        network = ipaddress.ip_network(str(value or "").strip(), strict=False)
    except ValueError as exc:
        raise PbrIntentError(f"{label} must be an IPv4 CIDR") from exc
    if network.version != 4:
        raise PbrIntentError(f"{label} must be an IPv4 CIDR")
    if bounded and network.prefixlen == 0:
        raise PbrIntentError(f"{label} must be a bounded IPv4 CIDR")
    return str(network)


@dataclass(frozen=True)
class NormalizedPbrIntent:
    attributes: Mapping[str, Any]


def normalize_pbr_intent(pbr: Mapping[str, Any]) -> NormalizedPbrIntent:
    if pbr.get("enabled") is not True:
        raise PbrIntentError("PBR intent requires enabled=true")

    strategy = str(pbr.get("strategy") or "routing_rules").strip()
    if strategy != "routing_rules":
        raise PbrIntentError("PBR v0.1 supports only strategy=routing_rules")

    raw_rules = pbr.get("rules")
    if not isinstance(raw_rules, list) or not raw_rules:
        raise PbrIntentError("pbr.rules must be a non-empty list")

    names: set[str] = set()
    matches: set[tuple[str, str, str | None, str]] = set()
    rules: list[dict[str, Any]] = []
    for index, raw in enumerate(raw_rules):
        if not isinstance(raw, Mapping):
            raise PbrIntentError(f"pbr.rules[{index}] must be an object")
        name = _name(raw.get("name"), f"pbr.rules[{index}].name")
        if name in names:
            raise PbrIntentError(f"duplicate PBR rule name: {name}")
        names.add(name)

        source = _network(
            raw.get("source_cidr"),
            f"pbr.rules[{index}].source_cidr",
            bounded=True,
        )
        destination_raw = raw.get("destination_cidr")
        destination = (
            _network(
                destination_raw,
                f"pbr.rules[{index}].destination_cidr",
                bounded=False,
            )
            if destination_raw is not None
            else "0.0.0.0/0"
        )
        interface_raw = raw.get("in_interface")
        interface = (
            _name(interface_raw, f"pbr.rules[{index}].in_interface")
            if interface_raw is not None
            else None
        )
        table = _name(raw.get("table"), f"pbr.rules[{index}].table")
        if table == "main":
            raise PbrIntentError("PBR rule must reference a dedicated non-main routing table")

        action = str(raw.get("action") or "lookup").strip()
        if action not in {"lookup", "lookup_only"}:
            raise PbrIntentError(
                f"pbr.rules[{index}].action must be lookup or lookup_only"
            )

        key = (source, destination, interface, table)
        if key in matches:
            raise PbrIntentError("duplicate PBR match/table combination")
        matches.add(key)

        rules.append(
            {
                "name": name,
                "source_cidr": source,
                "destination_cidr": destination,
                "in_interface": interface,
                "table": table,
                "action": action,
                "fallback_to_main": action == "lookup",
            }
        )

    rules.sort(key=lambda item: str(item["name"]))
    return NormalizedPbrIntent(
        attributes={
            "enabled": True,
            "strategy": "routing_rules",
            "mangle_routing_marks": False,
            "rules": rules,
        }
    )
