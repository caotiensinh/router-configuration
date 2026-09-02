from __future__ import annotations

from dataclasses import dataclass
from ipaddress import ip_network


@dataclass(frozen=True)
class Zone:
    name: str
    cidr: str
    internet_access: bool = True

    def __post_init__(self) -> None:
        if not self.name.strip():
            raise ValueError("zone name must not be empty")
        ip_network(self.cidr, strict=False)


@dataclass(frozen=True)
class InterZoneRule:
    source_zone: str
    destination_zone: str
    allow: bool


@dataclass(frozen=True)
class PolicyRoute:
    name: str
    source_zone: str
    preferred_wan: str
    fallback_wan: str | None = None


@dataclass(frozen=True)
class QosClass:
    name: str
    priority: int
    tags: tuple[str, ...]

    def __post_init__(self) -> None:
        if not 1 <= self.priority <= 8:
            raise ValueError("QoS priority must be between 1 and 8")


@dataclass(frozen=True)
class TrafficPolicy:
    zones: tuple[Zone, ...]
    interzone_rules: tuple[InterZoneRule, ...] = ()
    policy_routes: tuple[PolicyRoute, ...] = ()
    qos_classes: tuple[QosClass, ...] = ()


class TrafficPolicyValidator:
    def validate(self, policy: TrafficPolicy) -> tuple[str, ...]:
        errors: list[str] = []
        zone_names = [zone.name for zone in policy.zones]
        unique_zones = set(zone_names)

        if len(zone_names) != len(unique_zones):
            errors.append("zone names must be unique")

        networks = []
        for zone in policy.zones:
            network = ip_network(zone.cidr, strict=False)
            for other_name, other_network in networks:
                if network.overlaps(other_network):
                    errors.append(
                        f"zone networks overlap: {zone.name} and {other_name}"
                    )
            networks.append((zone.name, network))

        for rule in policy.interzone_rules:
            if rule.source_zone not in unique_zones:
                errors.append(f"unknown source zone: {rule.source_zone}")
            if rule.destination_zone not in unique_zones:
                errors.append(f"unknown destination zone: {rule.destination_zone}")
            if rule.source_zone == rule.destination_zone:
                errors.append("inter-zone rule must reference two different zones")

        route_names: set[str] = set()
        for route in policy.policy_routes:
            if route.name in route_names:
                errors.append(f"duplicate policy route name: {route.name}")
            route_names.add(route.name)
            if route.source_zone not in unique_zones:
                errors.append(f"policy route references unknown zone: {route.source_zone}")
            if route.fallback_wan and route.fallback_wan == route.preferred_wan:
                errors.append(
                    f"policy route {route.name} uses the same preferred and fallback WAN"
                )

        qos_names: set[str] = set()
        for qos in policy.qos_classes:
            if qos.name in qos_names:
                errors.append(f"duplicate QoS class name: {qos.name}")
            qos_names.add(qos.name)

        return tuple(errors)
