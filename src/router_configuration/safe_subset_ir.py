from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from enum import IntEnum
from typing import Any, Mapping

from .deployment_profile import DeploymentProfileValidator
from .m04_multiwan import MultiWanPlanner, WanLink


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

    def _compile_security(self, intent: Mapping[str, Any]) -> list[IntentOperation]:
        security = intent.get("security")
        if not isinstance(security, Mapping):
            return []
        if bool(security.get("management_from_wan", False)):
            raise ValueError("safe subset v0.1 refuses management_from_wan=true")
        return [
            IntentOperation(
                operation_id="security.baseline",
                feature="security",
                resource="firewall_baseline",
                attributes={
                    "profile": str(security.get("profile") or "enterprise_baseline"),
                    "wan_input_default": str(security.get("wan_input_default") or "deny"),
                    "management_from_wan": False,
                },
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
        secret_ref = str(wireguard.get("secret_ref") or "").strip()
        if not secret_ref.startswith(("env://", "vault://", "keyring://")):
            raise ValueError("WireGuard intent requires an unresolved secret reference")
        return [
            IntentOperation(
                operation_id="vpn.wireguard",
                feature="vpn",
                resource="wireguard_policy",
                attributes={"enabled": True},
                risk=IntentRisk.HIGH,
                requires=("wireguard", "firewall", "management_path"),
                secret_references=(secret_ref,),
            )
        ]

    def _compile_qos(self, intent: Mapping[str, Any]) -> list[IntentOperation]:
        qos = intent.get("qos")
        if not isinstance(qos, Mapping) or not bool(qos.get("enabled", False)):
            return []
        return [
            IntentOperation(
                operation_id="qos.policy",
                feature="qos",
                resource="traffic_policy",
                attributes={"policy": str(qos.get("policy") or "latency_sensitive_first")},
                risk=IntentRisk.MEDIUM,
                requires=("qos",),
            )
        ]
