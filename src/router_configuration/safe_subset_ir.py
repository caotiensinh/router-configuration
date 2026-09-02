from __future__ import annotations

import hashlib
import ipaddress
import json
from dataclasses import dataclass
from enum import IntEnum
from typing import Any, Mapping

from .deployment_profile import DeploymentProfileValidator
from .m04_multiwan import MultiWanPlanner, WanLink
from .m06_security import FindingSeverity, SecurityBaseline, SecurityPolicyValidator
from .qos_intent import normalize_qos_intent
from .wireguard_intent import normalize_wireguard_intent


class IntentRisk(IntEnum):
    LOW = 10
    MEDIUM = 20
    HIGH = 30
    CRITICAL = 40


@dataclass(frozen=True)
class IntentOperation:
    operation_id: str
    feature: str
    resource: str
    attributes: Mapping[str, Any]
    risk: IntentRisk
    requires: tuple[str, ...] = ()
    secret_references: tuple[str, ...] = ()

    def as_dict(self) -> dict[str, Any]:
        return {
            "operation_id": self.operation_id,
            "feature": self.feature,
            "resource": self.resource,
            "attributes": dict(self.attributes),
            "risk": int(self.risk),
            "requires": list(self.requires),
            "secret_references": list(self.secret_references),
        }


@dataclass(frozen=True)
class SafeSubsetIR:
    device_id: str
    operations: tuple[IntentOperation, ...]

    def as_dict(self) -> dict[str, Any]:
        payload = {
            "schema_version": "config-safe-subset-ir/1",
            "device_id": self.device_id,
            "operations": [item.as_dict() for item in self.operations],
            "vendor_commands_present": False,
            "write_transport_present": False,
        }
        canonical = json.dumps(
            payload,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=False,
        ).encode("utf-8")
        payload["ir_sha256"] = hashlib.sha256(canonical).hexdigest()
        return payload


class SafeSubsetCompiler:
    """Compile a guided profile into a vendor-neutral, non-executable IR.

    The output describes requested network behavior only. It intentionally has
    no RouterOS command strings, REST methods, credentials, resolved secrets or
    write transport. A vendor renderer may consume this IR only after the live
    discovery acceptance gate is satisfied.
    """

    def compile(self, profile: Mapping[str, Any]) -> SafeSubsetIR:
        validation = DeploymentProfileValidator().validate(profile)
        if not validation.ok or validation.deployment_spec is None:
            raise ValueError("deployment profile must pass validation before IR compilation")

        spec = validation.deployment_spec
        topology = profile.get("topology", {})
        intent = profile.get("intent", {})
        if not isinstance(topology, Mapping) or not isinstance(intent, Mapping):
            raise ValueError("profile topology and intent must be objects")

        operations: list[IntentOperation] = []
        operations.extend(self._compile_topology(topology))
        operations.extend(self._compile_multiwan(topology, intent))
        operations.extend(self._compile_security(intent))
        operations.extend(self._compile_vpn(intent))
        operations.extend(self._compile_qos(intent))
        operations.sort(key=lambda item: item.operation_id)
        return SafeSubsetIR(device_id=spec.device_id, operations=tuple(operations))

    def _compile_topology(self, topology: Mapping[str, Any]) -> list[IntentOperation]:
        operations: list[IntentOperation] = []
        wans = topology.get("wans", [])
        if isinstance(wans, list):
            for wan in wans:
                if not isinstance(wan, Mapping) or not bool(wan.get("enabled", True)):
                    continue
                name = str(wan.get("name") or "").strip()
                interface = str(wan.get("interface") or "").strip()
                attributes: dict[str, Any] = {
                    "name": name,
                    "interface": interface,
                    "capacity_mbps": int(wan.get("capacity_mbps", 0)),
                    "addressing": str(wan.get("addressing") or "isp_defined"),
                }
                address = str(wan.get("address") or "").strip()
                if address:
                    attributes["address"] = address
                operations.append(
                    IntentOperation(
                        operation_id=f"topology.wan.{name}",
                        feature="topology",
                        resource="wan_role",
                        attributes=attributes,
                        risk=IntentRisk.MEDIUM,
                        requires=("interfaces",),
                    )
                )

        core = topology.get("core")
        if isinstance(core, Mapping):
            operations.append(
                IntentOperation(
                    operation_id="topology.core",
                    feature="topology",
                    resource="core_uplink_role",
                    attributes={
                        "interface": str(core.get("interface") or "").strip(),
                        "capacity_mbps": int(core.get("capacity_mbps", 0)),
                    },
                    risk=IntentRisk.MEDIUM,
                    requires=("interfaces",),
                )
            )
        return operations

    def _compile_multiwan(
        self,
        topology: Mapping[str, Any],
        intent: Mapping[str, Any],
    ) -> list[IntentOperation]:
        multiwan = intent.get("multiwan")
        if not isinstance(multiwan, Mapping):
            return []
        if str(multiwan.get("mode") or "") != "capacity_weighted":
            raise ValueError("safe subset v0.1 supports only capacity_weighted multi-WAN")

        links: list[WanLink] = []
        paths: dict[str, dict[str, Any]] = {}
        for wan in topology.get("wans", []):
            if not isinstance(wan, Mapping) or not bool(wan.get("enabled", True)):
                continue
            name = str(wan.get("name") or "").strip()
            links.append(
                WanLink(
                    name=name,
                    capacity_mbps=int(wan.get("capacity_mbps", 0)),
                )
            )
            routing = wan.get("routing")
            if isinstance(routing, Mapping):
                path: dict[str, Any] = {
                    "interface": str(wan.get("interface") or "").strip(),
                    "addressing": str(wan.get("addressing") or "isp_defined").strip(),
                    "gateway": str(routing.get("gateway") or "").strip(),
                    "table": str(routing.get("table") or "").strip(),
                    "failover_distance": int(routing.get("failover_distance", 0)),
                    "health_probe_targets": [
                        str(value).strip()
                        for value in routing.get("health_probe_targets", [])
                    ],
                }
                address = str(wan.get("address") or "").strip()
                if address:
                    path["address"] = address
                paths[name] = path

        policy = MultiWanPlanner().derive_capacity_weights(links)
        attributes: dict[str, Any] = {
            "mode": "capacity_weighted",
            "weights": dict(policy.weights),
            "failover": bool(multiwan.get("failover", False)),
            "failback": str(multiwan.get("failback") or "manual"),
        }
        if paths:
            attributes["paths"] = paths
        return [
            IntentOperation(
                operation_id="routing.multiwan.capacity_weighted",
                feature="multiwan",
                resource="path_distribution_policy",
                attributes=attributes,
                risk=IntentRisk.HIGH,
                requires=("interfaces", "routing"),
            )
        ]

    @staticmethod
    def _normalize_required_wan_services(raw: Any) -> list[dict[str, Any]]:
        if not isinstance(raw, list):
            raise ValueError("security.required_wan_services must be a list")
        normalized: list[dict[str, Any]] = []
        seen: set[tuple[str, int, tuple[str, ...]]] = set()
        for index, item in enumerate(raw):
            if not isinstance(item, Mapping):
                raise ValueError(f"security.required_wan_services[{index}] must be an object")
            name = str(item.get("name") or "").strip()
            protocol = str(item.get("protocol") or "").strip().lower()
            dst_port = item.get("dst_port")
            sources_raw = item.get("source_cidrs")
            if not name:
                raise ValueError(f"security.required_wan_services[{index}].name is required")
            if protocol not in {"tcp", "udp"}:
                raise ValueError(
                    f"security.required_wan_services[{index}].protocol must be tcp or udp"
                )
            if isinstance(dst_port, bool) or not isinstance(dst_port, int) or not 1 <= dst_port <= 65535:
                raise ValueError(
                    f"security.required_wan_services[{index}].dst_port must be an integer from 1 to 65535"
                )
            if not isinstance(sources_raw, list) or not sources_raw:
                raise ValueError(
                    f"security.required_wan_services[{index}].source_cidrs requires at least one bounded CIDR"
                )
            sources: list[str] = []
            for source_index, value in enumerate(sources_raw):
                text = str(value or "").strip()
                try:
                    network = ipaddress.ip_network(text, strict=False)
                except ValueError as exc:
                    raise ValueError(
                        f"security.required_wan_services[{index}].source_cidrs[{source_index}] must be a CIDR"
                    ) from exc
                if network.version != 4 or network.prefixlen == 0:
                    raise ValueError(
                        f"security.required_wan_services[{index}].source_cidrs must be bounded IPv4 CIDRs"
                    )
                sources.append(str(network))
            sources = sorted(set(sources))
            key = (protocol, dst_port, tuple(sources))
            if key in seen:
                raise ValueError("security.required_wan_services contains a duplicate service rule")
            seen.add(key)
            normalized.append(
                {
                    "name": name,
                    "protocol": protocol,
                    "dst_port": dst_port,
                    "source_cidrs": sources,
                }
            )
        normalized.sort(key=lambda item: (str(item["protocol"]), int(item["dst_port"]), str(item["name"])))
        return normalized

    def _compile_security(self, intent: Mapping[str, Any]) -> list[IntentOperation]:
        security = intent.get("security")
        if not isinstance(security, Mapping):
            return []
        if bool(security.get("management_from_wan", False)):
            raise ValueError("safe subset v0.1 refuses management_from_wan=true")

        profile = str(security.get("profile") or "enterprise_baseline")
        wan_input_default = str(security.get("wan_input_default") or "deny")
        if profile != "enterprise_baseline":
            raise ValueError("safe subset v0.1 supports only security.profile=enterprise_baseline")
        if wan_input_default != "deny":
            raise ValueError("safe subset v0.1 requires security.wan_input_default=deny")

        attributes: dict[str, Any] = {
            "profile": profile,
            "wan_input_default": wan_input_default,
            "management_from_wan": False,
        }

        if "management_sources" in security:
            raw_sources = security.get("management_sources")
            if not isinstance(raw_sources, list):
                raise ValueError("security.management_sources must be a list")
            sources = tuple(str(value or "").strip() for value in raw_sources)
            anti_spoofing = security.get("anti_spoofing", True)
            if anti_spoofing is not True:
                raise ValueError("enterprise firewall baseline requires security.anti_spoofing=true")
            baseline = SecurityBaseline(
                management_sources=sources,
                default_wan_input_deny=True,
                anti_spoofing=True,
            )
            blocking = [
                finding.message
                for finding in SecurityPolicyValidator().validate(baseline)
                if finding.severity is FindingSeverity.ERROR
            ]
            if blocking:
                raise ValueError("security baseline: " + "; ".join(blocking))
            normalized_sources = sorted(
                {
                    str(ipaddress.ip_network(source, strict=False))
                    for source in sources
                }
            )
            attributes["management_sources"] = normalized_sources
            attributes["anti_spoofing"] = True
            icmp_policy = str(security.get("icmp_policy") or "essential_ipv4")
            if icmp_policy != "essential_ipv4":
                raise ValueError("safe subset v0.1 supports only security.icmp_policy=essential_ipv4")
            attributes["icmp_policy"] = icmp_policy

        if "required_wan_services" in security:
            attributes["required_wan_services"] = self._normalize_required_wan_services(
                security.get("required_wan_services")
            )

        return [
            IntentOperation(
                operation_id="security.baseline",
                feature="security",
                resource="firewall_baseline",
                attributes=attributes,
                risk=IntentRisk.HIGH,
                requires=("firewall", "nat", "management_path"),
            )
        ]

    def _compile_vpn(self, intent: Mapping[str, Any]) -> list[IntentOperation]:
        vpn = intent.get("vpn")
        if not isinstance(vpn, Mapping):
            return []
        wireguard = vpn.get("wireguard")
        if not isinstance(wireguard, Mapping) or not bool(wireguard.get("enabled", False)):
            return []
        normalized = normalize_wireguard_intent(wireguard)
        return [
            IntentOperation(
                operation_id="vpn.wireguard",
                feature="vpn",
                resource="wireguard_policy",
                attributes=normalized.attributes,
                risk=IntentRisk.HIGH,
                requires=("wireguard", "firewall", "management_path"),
                secret_references=(normalized.secret_ref,),
            )
        ]

    def _compile_qos(self, intent: Mapping[str, Any]) -> list[IntentOperation]:
        qos = intent.get("qos")
        if not isinstance(qos, Mapping) or not bool(qos.get("enabled", False)):
            return []
        normalized = normalize_qos_intent(qos)
        return [
            IntentOperation(
                operation_id="qos.policy",
                feature="qos",
                resource="traffic_policy",
                attributes=normalized.attributes,
                risk=IntentRisk.MEDIUM,
                requires=("qos",),
            )
        ]
